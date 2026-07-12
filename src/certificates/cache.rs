use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Default)]
pub struct CertificateCache {
    inner: Arc<Mutex<HashMap<String, CachedCertificate>>>,
}

#[derive(Debug, Clone)]
pub struct CachedCertificate {
    pub cert_pem: String,
    pub key_pem: String,
}

impl CertificateCache {
    pub fn get(&self, host: &str) -> Option<CachedCertificate> {
        self.inner
            .lock()
            .ok()
            .and_then(|cache| cache.get(host).cloned())
    }

    pub fn insert(&self, host: String, certificate: CachedCertificate) {
        if let Ok(mut cache) = self.inner.lock() {
            cache.insert(host, certificate);
        }
    }
}
