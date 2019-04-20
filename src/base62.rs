use base_x;
use std::io::{Error, ErrorKind};

const BASE62_ALPHABET: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

pub fn encode(input: &[u8]) -> String {
    base_x::encode(BASE62_ALPHABET, input)
}

pub fn decode(input: &str) -> Result<Vec<u8>, Error> {
    base_x::decode(BASE62_ALPHABET, input)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Error decoding base62 input"))
}

#[cfg(test)]
mod tests {
    use crate::base62::{decode, encode};
    use std::str;

    #[test]
    fn test_base62_decode() {
        let encoded = "1wJfrzvdbtXUOlUjUf";
        let decoded = decode(encoded).unwrap();
        println!("{:x?}", decoded);
        assert_eq!("Hello, World!", str::from_utf8(&decoded).unwrap());
    }

    #[test]
    fn test_base62_encode() {
        let text = "Hello, World!";
        let encoded = encode(text.as_bytes());
        assert_eq!("1wJfrzvdbtXUOlUjUf", encoded);
    }
}
