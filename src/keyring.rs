use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
use std::collections::HashMap;

pub struct KeyRing {
    encryption_keys: HashMap<PublicKey, SecretKey>,
    signing_keys: HashMap<PublicKey, SecretKey>
}

impl KeyRing {
    pub fn new() -> Self {
        KeyRing {
            encryption_keys: HashMap::new(),
            signing_keys: HashMap::new(),
        }
    }

    pub fn add_encryption_keys(&mut self, public_key: PublicKey, secret_key: SecretKey) {
        self.encryption_keys.insert(public_key, secret_key);
    }

    pub fn find_encryption_key(&self, public_key: &PublicKey) -> Option<&SecretKey> {
        self.encryption_keys.get(public_key)
    }

    pub fn get_all_encryption_keys(&self) -> Vec<&SecretKey> {
        self.encryption_keys.values().collect()
    }

    pub fn find_signing_key(&self, public_key: &PublicKey) -> Option<&SecretKey> {
        self.signing_keys.get(public_key)
    }
}
