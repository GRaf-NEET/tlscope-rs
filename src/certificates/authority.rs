use crate::certificates::cache::{CachedCertificate, CertificateCache};
use anyhow::{anyhow, Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, BufReader, Write},
    path::{Path, PathBuf},
};
use time::{Duration as TimeDuration, OffsetDateTime};

const CA_CERT_FILE: &str = "TLScope-ca.pem";
const CA_KEY_FILE: &str = "TLScope-ca-key.pem";
const MARKER_FILE: &str = "TLScope-created";
const VALIDITY_BACKDATE_DAYS: i64 = 1;
const CA_VALIDITY_DAYS: i64 = 3650;
const LEAF_VALIDITY_DAYS: i64 = 90;

pub struct LocalAuthority {
    cert_path: PathBuf,
    cert_pem: String,
    signer: Certificate,
    key_pair: KeyPair,
    cache: CertificateCache,
}

#[derive(Debug)]
pub struct LeafCertificate {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
}

impl Clone for LeafCertificate {
    fn clone(&self) -> Self {
        Self {
            cert_chain: self.cert_chain.clone(),
            private_key: self.private_key.clone_key(),
        }
    }
}

impl LocalAuthority {
    pub fn load_or_create(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);
        if cert_path.exists() && key_path.exists() {
            if should_recreate_legacy_ca(&dir, &cert_path)? {
                Self::create(dir)
            } else {
                Self::load(dir)
            }
        } else {
            Self::create(dir)
        }
    }

    pub fn create(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)
            .with_context(|| format!("cannot create CA directory {}", dir.display()))?;

        let mut params = CertificateParams::new(vec!["TLScope Local Debugging CA".to_string()])
            .context("cannot build CA certificate parameters")?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        params.distinguished_name = ca_distinguished_name();
        set_validity(&mut params, CA_VALIDITY_DAYS);

        let key_pair = KeyPair::generate().context("cannot generate CA private key")?;
        let signer = params
            .self_signed(&key_pair)
            .context("cannot create local CA")?;
        let cert_pem = signer.pem();
        let key_pem = key_pair.serialize_pem();

        fs::write(cert_path(&dir), &cert_pem).with_context(|| {
            format!(
                "cannot write CA certificate to {}",
                cert_path(&dir).display()
            )
        })?;
        write_private_key(&key_path(&dir), &key_pem)?;
        fs::write(dir.join(MARKER_FILE), b"TLScope\n")
            .with_context(|| format!("cannot write CA marker in {}", dir.display()))?;

        Self::load(dir)
    }

    pub fn load(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let cert_path = cert_path(&dir);
        let key_path = key_path(&dir);
        let cert_pem = fs::read_to_string(&cert_path)
            .with_context(|| format!("cannot read CA certificate {}", cert_path.display()))?;
        let key_pem = fs::read_to_string(&key_path)
            .with_context(|| format!("cannot read CA private key {}", key_path.display()))?;
        let key_pair = KeyPair::from_pem(&key_pem).context("cannot parse CA private key")?;
        let params = CertificateParams::from_ca_cert_pem(&cert_pem)
            .context("cannot parse CA certificate")?;
        let signer = params
            .self_signed(&key_pair)
            .context("cannot load CA signer")?;
        Ok(Self {
            cert_path,
            cert_pem,
            signer,
            key_pair,
            cache: CertificateCache::default(),
        })
    }

    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn fingerprint(&self) -> Result<String> {
        fingerprint_pem(&self.cert_pem)
    }

    pub fn leaf_for_host(&self, host: &str) -> Result<LeafCertificate> {
        let host = normalize_host(host);
        let cached = if let Some(cached) = self.cache.get(&host) {
            cached
        } else {
            let generated = self.generate_leaf_pem(&host)?;
            self.cache.insert(host.clone(), generated.clone());
            generated
        };
        leaf_from_pem(&cached.cert_pem, &cached.key_pem)
    }

    pub fn remove_created_files(dir: impl AsRef<Path>, confirmed: bool) -> Result<bool> {
        let dir = dir.as_ref();
        let marker = dir.join(MARKER_FILE);
        if !marker.exists() || !confirmed {
            return Ok(false);
        }
        for path in [cert_path(dir), key_path(dir), marker] {
            if path.exists() {
                fs::remove_file(&path)
                    .with_context(|| format!("cannot remove {}", path.display()))?;
            }
        }
        Ok(true)
    }

    pub fn prompt_remove_confirmation(dir: &Path) -> Result<bool> {
        print!(
            "Remove local CA files created by TLScope in {}? Type 'remove' to confirm: ",
            dir.display()
        );
        io::stdout().flush().ok();
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .context("cannot read confirmation")?;
        Ok(input.trim() == "remove")
    }

    fn generate_leaf_pem(&self, host: &str) -> Result<CachedCertificate> {
        let mut params = CertificateParams::new(vec![host.to_string()])
            .context("cannot build leaf certificate parameters")?;
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, host);
            dn
        };
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        set_validity(&mut params, LEAF_VALIDITY_DAYS);
        let leaf_key = KeyPair::generate().context("cannot generate leaf private key")?;
        let cert = params
            .signed_by(&leaf_key, &self.signer, &self.key_pair)
            .context("cannot sign leaf certificate")?;
        Ok(CachedCertificate {
            cert_pem: cert.pem(),
            key_pem: leaf_key.serialize_pem(),
        })
    }
}

pub fn ca_cert_path(dir: impl AsRef<Path>) -> PathBuf {
    cert_path(dir.as_ref())
}

pub fn ca_fingerprint_from_dir(dir: impl AsRef<Path>) -> Result<String> {
    let path = cert_path(dir.as_ref());
    let pem = fs::read_to_string(&path)
        .with_context(|| format!("cannot read CA certificate {}", path.display()))?;
    fingerprint_pem(&pem)
}

pub fn fingerprint_pem(pem: &str) -> Result<String> {
    let mut reader = BufReader::new(pem.as_bytes());
    let cert = {
        let mut certs = rustls_pemfile::certs(&mut reader);
        certs
            .next()
            .transpose()
            .context("cannot parse certificate PEM")?
            .ok_or_else(|| anyhow!("certificate PEM does not contain a certificate"))?
    };
    Ok(hex::encode_upper(Sha256::digest(cert.as_ref())))
}

fn leaf_from_pem(cert_pem: &str, key_pem: &str) -> Result<LeafCertificate> {
    let mut cert_reader = BufReader::new(cert_pem.as_bytes());
    let cert_chain = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("cannot parse generated certificate")?;
    let mut key_reader = BufReader::new(key_pem.as_bytes());
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .context("cannot parse generated private key")?
        .ok_or_else(|| anyhow!("generated certificate has no private key"))?;
    Ok(LeafCertificate {
        cert_chain,
        private_key,
    })
}

fn write_private_key(path: &Path, key_pem: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("cannot write CA private key to {}", path.display()))?;
        file.write_all(key_pem.as_bytes())
            .with_context(|| format!("cannot write CA private key to {}", path.display()))?;
    }

    #[cfg(not(unix))]
    {
        fs::write(path, key_pem)
            .with_context(|| format!("cannot write CA private key to {}", path.display()))?;
    }
    Ok(())
}

fn ca_distinguished_name() -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "TLScope Local Debugging CA");
    dn.push(DnType::OrganizationName, "TLScope local");
    dn
}

fn set_validity(params: &mut CertificateParams, valid_for_days: i64) {
    let now = OffsetDateTime::now_utc();
    params.not_before = now - TimeDuration::days(VALIDITY_BACKDATE_DAYS);
    params.not_after = now + TimeDuration::days(valid_for_days);
}

fn should_recreate_legacy_ca(dir: &Path, cert_path: &Path) -> Result<bool> {
    if !dir.join(MARKER_FILE).exists() {
        return Ok(false);
    }
    let cert_pem = fs::read_to_string(cert_path)
        .with_context(|| format!("cannot read CA certificate {}", cert_path.display()))?;
    let params = CertificateParams::from_ca_cert_pem(&cert_pem)
        .context("cannot parse existing CA certificate")?;
    Ok(has_rcgen_default_validity(
        params.not_before,
        params.not_after,
    ))
}

fn has_rcgen_default_validity(not_before: OffsetDateTime, not_after: OffsetDateTime) -> bool {
    not_before.year() <= 1975 && not_after.year() >= 4096
}

fn normalize_host(host: &str) -> String {
    host.trim_matches('[')
        .trim_matches(']')
        .to_ascii_lowercase()
}

fn cert_path(dir: &Path) -> PathBuf {
    dir.join(CA_CERT_FILE)
}

fn key_path(dir: &Path) -> PathBuf {
    dir.join(CA_KEY_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::{FromDer, X509Certificate};

    #[test]
    fn creates_ca_and_leaf_certificate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = LocalAuthority::load_or_create(dir.path()).expect("create ca");
        assert!(ca.cert_path().exists());
        assert!(!ca.fingerprint().expect("fingerprint").is_empty());
        let (ca_not_before, ca_not_after) = pem_validity(ca.cert_pem());
        assert_valid_current_window(ca_not_before, ca_not_after, CA_VALIDITY_DAYS + 1);

        let leaf = ca.leaf_for_host("localhost").expect("leaf");
        assert!(!leaf.cert_chain.is_empty());
        let (leaf_not_before, leaf_not_after) = der_validity(&leaf.cert_chain[0]);
        assert_valid_current_window(leaf_not_before, leaf_not_after, LEAF_VALIDITY_DAYS + 1);
        assert!(!has_rcgen_default_validity(leaf_not_before, leaf_not_after));
    }

    #[test]
    fn remove_only_with_marker_and_confirmation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _ca = LocalAuthority::load_or_create(dir.path()).expect("create ca");
        assert!(!LocalAuthority::remove_created_files(dir.path(), false).expect("remove"));
        assert!(LocalAuthority::remove_created_files(dir.path(), true).expect("remove"));
        assert!(!cert_path(dir.path()).exists());
        assert!(!key_path(dir.path()).exists());
    }

    #[test]
    fn load_or_create_replaces_owned_legacy_default_validity_ca() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path()).expect("create temp ca dir");

        let mut params = CertificateParams::new(vec!["TLScope Local Debugging CA".to_string()])
            .expect("legacy params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        params.distinguished_name = ca_distinguished_name();
        let key_pair = KeyPair::generate().expect("legacy key");
        let cert = params.self_signed(&key_pair).expect("legacy ca");

        fs::write(cert_path(dir.path()), cert.pem()).expect("write legacy cert");
        write_private_key(&key_path(dir.path()), &key_pair.serialize_pem())
            .expect("write legacy key");
        fs::write(dir.path().join(MARKER_FILE), b"TLScope\n").expect("write marker");

        let (legacy_not_before, legacy_not_after) =
            pem_validity(&fs::read_to_string(cert_path(dir.path())).expect("read legacy"));
        assert!(has_rcgen_default_validity(
            legacy_not_before,
            legacy_not_after
        ));

        let ca = LocalAuthority::load_or_create(dir.path()).expect("reload ca");
        let (not_before, not_after) = pem_validity(ca.cert_pem());
        assert_valid_current_window(not_before, not_after, CA_VALIDITY_DAYS + 1);
        assert!(!has_rcgen_default_validity(not_before, not_after));
    }

    fn pem_validity(pem: &str) -> (OffsetDateTime, OffsetDateTime) {
        let mut reader = BufReader::new(pem.as_bytes());
        let cert = rustls_pemfile::certs(&mut reader)
            .next()
            .transpose()
            .expect("parse pem")
            .expect("pem cert");
        der_validity(&cert)
    }

    fn der_validity(cert: &CertificateDer<'_>) -> (OffsetDateTime, OffsetDateTime) {
        let (_, parsed) = X509Certificate::from_der(cert.as_ref()).expect("parse cert");
        (
            parsed.validity().not_before.to_datetime(),
            parsed.validity().not_after.to_datetime(),
        )
    }

    fn assert_valid_current_window(
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
        max_days_from_now: i64,
    ) {
        let now = OffsetDateTime::now_utc();
        assert!(not_before <= now);
        assert!(not_after > now);
        assert!(not_after - now <= TimeDuration::days(max_days_from_now));
    }
}
