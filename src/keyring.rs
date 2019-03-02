use crate::cryptotypes::{PublicKey, SecretKey};
use std::collections::HashMap;

pub struct KeyRing {
    encryption_keys: HashMap<PublicKey, SecretKey>,
    signing_keys: HashMap<PublicKey, SecretKey>
}

impl KeyRing {
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
