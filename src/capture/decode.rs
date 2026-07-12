use crate::capture::model::CapturedBody;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use std::io::Read;

const DEFAULT_PREVIEW_DECODE_LIMIT: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPreview {
    pub bytes: Vec<u8>,
    pub transfer_decoded: bool,
    pub content_decoded: bool,
    pub warnings: Vec<String>,
}

pub fn decode_body_for_preview(body: &CapturedBody) -> DecodedPreview {
    decode_body_for_preview_with_limit(body, DEFAULT_PREVIEW_DECODE_LIMIT)
}

pub fn decode_body_for_preview_with_limit(
    body: &CapturedBody,
    max_decoded_size: usize,
) -> DecodedPreview {
    let mut bytes = body.bytes.clone();
    let mut transfer_decoded = false;
    let mut content_decoded = false;
    let mut warnings = Vec::new();

    if has_token(body.transfer_encoding.as_deref(), "chunked") {
        match decode_chunked(&bytes, max_decoded_size) {
            Ok(decoded) => {
                bytes = decoded.bytes;
                transfer_decoded = true;
                if decoded.truncated {
                    warnings.push("decoded chunked body was truncated for preview".to_string());
                }
            }
            Err(error) => warnings.push(format!("could not decode chunked body: {error}")),
        }
    }

    if let Some(content_encoding) = &body.content_encoding {
        for encoding in content_encoding.split(',').map(|part| part.trim()).rev() {
            if encoding.is_empty() || encoding.eq_ignore_ascii_case("identity") {
                continue;
            }
            match decode_content_encoding(&bytes, encoding, max_decoded_size) {
                Ok(decoded) => {
                    bytes = decoded.bytes;
                    content_decoded = true;
                    if decoded.truncated {
                        warnings.push(format!("decoded {encoding} body was truncated for preview"));
                    }
                }
                Err(error) => {
                    warnings.push(format!("could not decode {encoding} body: {error}"));
                    break;
                }
            }
        }
    }

    DecodedPreview {
        bytes,
        transfer_decoded,
        content_decoded,
        warnings,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodeBytes {
    bytes: Vec<u8>,
    truncated: bool,
}

fn decode_content_encoding(
    input: &[u8],
    encoding: &str,
    limit: usize,
) -> Result<DecodeBytes, String> {
    if encoding.eq_ignore_ascii_case("gzip") || encoding.eq_ignore_ascii_case("x-gzip") {
        read_limited(GzDecoder::new(input), limit)
    } else if encoding.eq_ignore_ascii_case("deflate") {
        read_limited(ZlibDecoder::new(input), limit)
            .or_else(|_| read_limited(DeflateDecoder::new(input), limit))
    } else {
        Err("unsupported content encoding".to_string())
    }
}

fn read_limited<R: Read>(reader: R, limit: usize) -> Result<DecodeBytes, String> {
    let mut limited = reader.take((limit as u64).saturating_add(1));
    let mut bytes = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let truncated = bytes.len() > limit;
    if truncated {
        bytes.truncate(limit);
    }
    Ok(DecodeBytes { bytes, truncated })
}

fn decode_chunked(input: &[u8], limit: usize) -> Result<DecodeBytes, String> {
    let mut pos = 0;
    let mut out = Vec::new();
    let mut truncated = false;

    loop {
        let line_end = input[pos..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|offset| pos + offset)
            .ok_or_else(|| "missing chunk size line ending".to_string())?;
        let mut line = &input[pos..line_end];
        if line.ends_with(b"\r") {
            line = &line[..line.len() - 1];
        }
        let size_text = std::str::from_utf8(line)
            .map_err(|_| "chunk size is not valid ASCII".to_string())?
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| format!("invalid chunk size '{size_text}'"))?;
        pos = line_end + 1;

        if size == 0 {
            break;
        }
        if input.len().saturating_sub(pos) < size {
            return Err("chunk data is incomplete".to_string());
        }
        if out.len() < limit {
            let remaining = limit - out.len();
            let keep = remaining.min(size);
            out.extend_from_slice(&input[pos..pos + keep]);
            truncated |= keep < size;
        } else {
            truncated = true;
        }
        pos += size;

        if input.get(pos) == Some(&b'\r') {
            pos += 1;
        }
        if input.get(pos) == Some(&b'\n') {
            pos += 1;
        } else {
            return Err("chunk data is missing trailing CRLF".to_string());
        }
    }

    Ok(DecodeBytes {
        bytes: out,
        truncated,
    })
}

fn has_token(value: Option<&str>, token: &str) -> bool {
    value
        .unwrap_or_default()
        .split(',')
        .any(|part| part.trim().eq_ignore_ascii_case(token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    #[test]
    fn decodes_chunked_gzip_body_for_preview() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(br#"{"ok":true}"#).unwrap();
        let gzip = encoder.finish().unwrap();
        let mut wire = format!("{:x}\r\n", gzip.len()).into_bytes();
        wire.extend_from_slice(&gzip);
        wire.extend_from_slice(b"\r\n0\r\n\r\n");

        let mut body = CapturedBody::from_bytes(
            &wire,
            4096,
            Some("application/json".to_string()),
            Some("gzip".to_string()),
        );
        body.transfer_encoding = Some("chunked".to_string());

        let decoded = decode_body_for_preview(&body);

        assert!(decoded.transfer_decoded);
        assert!(decoded.content_decoded);
        assert!(decoded.warnings.is_empty());
        assert_eq!(decoded.bytes, br#"{"ok":true}"#);
    }
}
