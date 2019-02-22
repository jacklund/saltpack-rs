#[derive(Debug)]
pub enum KeyError {
    LengthError(String),
}

pub type Key = [u8; 32];

pub fn from_binary(data: &[u8]) -> Result<Key, KeyError> {
    if data.len() != 32 {
        Err(KeyError::LengthError(format!(
            "Expected length 32, found length {}",
            data.len()
        )))
    } else {
        let mut key_data: [u8; 32] = [0; 32];
        key_data.copy_from_slice(data);
        Ok(key_data)
    }
}

pub type PublicKey = Key;

pub type SecretKey = Key;
