use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
use sodiumoxide::crypto::sign::PublicKey as PublicSigningKey;
use sodiumoxide::crypto::sign::SecretKey as SigningKey;
use std::collections::HashMap;

#[derive(Default)]
pub struct KeyRing {
    encryption_keys: HashMap<PublicKey, SecretKey>,
    signing_keys: HashMap<PublicSigningKey, SigningKey>,
}

impl KeyRing {
    pub fn add_encryption_keys(&mut self, public_key: PublicKey, secret_key: SecretKey) {
        self.encryption_keys.insert(public_key, secret_key);
    }

    pub fn find_encryption_key(&self, public_key: &PublicKey) -> Option<&SecretKey> {
        self.encryption_keys.get(public_key)
    }

    pub fn get_all_encryption_keys(&self) -> Vec<&SecretKey> {
        self.encryption_keys.values().collect()
    }

    pub fn add_signing_keys(&mut self, public_key: PublicSigningKey, signing_key: SigningKey) {
        self.signing_keys.insert(public_key, signing_key);
    }

    pub fn find_signing_key(&self, public_key: &PublicSigningKey) -> Option<&SigningKey> {
        self.signing_keys.get(public_key)
    }
}
