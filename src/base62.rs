use crate::error::Error;
use base_x;

const BASE62_ALPHABET: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

pub fn encode(input: &[u8]) -> String {
    base_x::encode(BASE62_ALPHABET, input)
}

pub fn add_spaces(input: &str) -> String {
    let mut index: usize = 15;
    let mut string: String = input.to_string();
    while index < string.len() {
        string.insert(index, ' ');
        index += 15;
    }

    string
}

pub fn remove_spaces(input: &str) -> String {
    if input.contains(" ") {
        input.replace(" ", "")
    } else {
        input.to_string()
    }
}

pub fn decode(input: &str) -> Result<Vec<u8>, Error> {
    base_x::decode(BASE62_ALPHABET, &remove_spaces(input)).map_err(|e| e.into())
}

#[cfg(test)]
mod tests {
    use crate::base62::{add_spaces, decode, encode};
    use std::str;

    #[test]
    fn test_base62_decode() {
        let encoded = "1wJfrzvdbtXUOlUjUf";
        let decoded = decode(encoded).unwrap();
        println!("{:x?}", decoded);
        assert_eq!("Hello, World!", str::from_utf8(&decoded).unwrap());
    }

    #[test]
    fn test_base62_decode_with_spaces() {
        let encoded = "1wJfrzvdbtXUOlU jUf";
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

    #[test]
    fn test_base62_encode_with_spaces() {
        let text = "Hello, World!";
        let encoded = add_spaces(&encode(text.as_bytes()));
        assert_eq!("1wJfrzvdbtXUOlU jUf", encoded);
    }
}
