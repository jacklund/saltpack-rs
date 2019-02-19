use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum KeyError {
    LengthError(String),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Key(pub [u8; 32]);

impl Key {
    pub fn from_binary(data: &[u8]) -> Result<Self, KeyError> {
        if data.len() != 32 {
            Err(KeyError::LengthError(format!("Expected length 32, found length {}", data.len())))
        } else {
            let mut key_data: [u8; 32] = [0; 32];
            key_data.copy_from_slice(data);
            Ok(Key(key_data))
        }
    }
}

pub type PublicKey = Key;

pub type SecretKey = Key;
