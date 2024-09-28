use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use tokio::fs;
use hex::encode as hex_encode;

use crate::NVDARemoteError;

#[derive(Serialize, Deserialize, Debug)]
pub struct FingerprintCache {
    fingerprints: HashMap<String, String>,  // host -> fingerprint (hex string)
}

impl FingerprintCache {
    // Load from file
    pub async fn load_from_file(path: &str) -> Result<Self, NVDARemoteError> {
        match fs::read_to_string(path).await {
            Ok(data) => {
                let cache: Self = serde_json::from_str(&data)?;
                Ok(cache)
            },
            Err(_) => {
                // If the file doesn't exist or is unreadable, create an empty cache
                Ok(Self { fingerprints: HashMap::new() })
            }
        }
    }

    // Save to file
    pub async fn save_to_file(&self, path: &str) -> Result<(), NVDARemoteError> {
        let data = serde_json::to_string_pretty(&self)?;
        fs::write(path, data).await?;
        Ok(())
    }

    // Check if the host's fingerprint is in the cache
    pub fn contains(&self, host: &str) -> bool {
        self.fingerprints.contains_key(host)
    }

    // Add a new fingerprint to the cache
    pub fn add_fingerprint(&mut self, host: String, fingerprint: Vec<u8>) {
        let fingerprint_hex = hex_encode(fingerprint); // Convert to hex string for easier handling
        self.fingerprints.insert(host, fingerprint_hex);
    }

    // Get the fingerprint for a specific host
    pub fn get_fingerprint(&self, host: &str) -> Option<Vec<u8>> {
        let fingerprint_hex = self.fingerprints.get(host)?;
        let fingerprint = hex::decode(fingerprint_hex).unwrap();  // Convert back to bytes
        Some(fingerprint)
    }

    pub fn to_cert_store(&self) -> rustls::RootCertStore {
        let mut store = rustls::RootCertStore::empty();
        for fingerprint in self.fingerprints.values() {
            let fingerprint = hex::decode(fingerprint).unwrap();
            store.add(fingerprint.into()).unwrap();
        }
        store
    }
}
