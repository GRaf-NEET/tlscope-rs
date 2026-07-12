use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildOutputStream {
    Stdout,
    Stderr,
}

impl ChildOutputStream {
    pub fn label(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildOutputLine {
    pub stream: ChildOutputStream,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct ChildLogSnapshot {
    pub lines: Vec<ChildOutputLine>,
    pub dropped: usize,
    pub total: usize,
}

impl Default for ChildLogSnapshot {
    fn default() -> Self {
        Self {
            lines: Vec::new(),
            dropped: 0,
            total: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChildLogStore {
    lines: VecDeque<ChildOutputLine>,
    max_lines: usize,
    dropped: usize,
    total: usize,
}

impl ChildLogStore {
    pub fn new(max_lines: usize) -> Self {
        Self {
            lines: VecDeque::with_capacity(max_lines.min(1024)),
            max_lines,
            dropped: 0,
            total: 0,
        }
    }

    pub fn push(&mut self, stream: ChildOutputStream, text: impl Into<String>) {
        if self.max_lines == 0 {
            self.dropped += 1;
            self.total += 1;
            return;
        }
        if self.lines.len() == self.max_lines {
            self.lines.pop_front();
            self.dropped += 1;
        }
        self.lines.push_back(ChildOutputLine {
            stream,
            text: text.into(),
        });
        self.total += 1;
    }

    pub fn snapshot(&self) -> ChildLogSnapshot {
        ChildLogSnapshot {
            lines: self.lines.iter().cloned().collect(),
            dropped: self.dropped,
            total: self.total,
        }
    }
}

impl Default for ChildLogStore {
    fn default() -> Self {
        Self::new(2_000)
    }
}

pub fn sanitize_output_line(bytes: &[u8], max_chars: usize) -> String {
    let mut end = bytes.len();
    while end > 0 && matches!(bytes[end - 1], b'\n' | b'\r') {
        end -= 1;
    }

    let decoded = String::from_utf8_lossy(&bytes[..end]);
    let stripped = strip_ansi_sequences(&decoded);
    let mut result = String::with_capacity(stripped.len().min(max_chars));
    let mut count = 0;
    let mut truncated = false;

    for ch in stripped.chars() {
        if count == max_chars {
            truncated = true;
            break;
        }
        if ch == '\t' || !ch.is_control() {
            result.push(ch);
        } else {
            result.push(' ');
        }
        count += 1;
    }

    if truncated {
        result.push_str("...");
    }
    result
}

fn strip_ansi_sequences(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && matches!(chars.peek(), Some('[')) {
            chars.next();
            for marker in chars.by_ref() {
                if ('@'..='~').contains(&marker) {
                    break;
                }
            }
            continue;
        }
        result.push(ch);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_recent_lines() {
        let mut store = ChildLogStore::new(2);
        store.push(ChildOutputStream::Stdout, "one");
        store.push(ChildOutputStream::Stderr, "two");
        store.push(ChildOutputStream::Stdout, "three");

        let snapshot = store.snapshot();
        assert_eq!(snapshot.dropped, 1);
        assert_eq!(snapshot.total, 3);
        assert_eq!(snapshot.lines.len(), 2);
        assert_eq!(snapshot.lines[0].text, "two");
        assert_eq!(snapshot.lines[1].text, "three");
    }
}
