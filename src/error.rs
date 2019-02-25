use rmp_serde::decode;
use std::convert::From;

#[derive(Debug)]
pub enum Error {
    DecodeError(decode::Error),
    DecryptionError(String),
    KeyLengthError(String),
    ValidationError(String),
}

impl From<decode::Error> for Error {
    fn from(e: decode::Error) -> Self {
        Error::DecodeError(e)
    }
}
