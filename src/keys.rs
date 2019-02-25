use crate::error::Error;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Key(pub [u8; 32]);

impl Key {
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 32 {
            Err(Error::KeyLengthError(format!(
                "Expected length 32, found length {}",
                data.len()
            )))
        } else {
            let mut key_data: [u8; 32] = [0; 32];
            key_data.copy_from_slice(data);
            Ok(Key(key_data))
        }
    }
}

impl std::convert::AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

pub type PublicKey = Key;

pub type SecretKey = Key;
