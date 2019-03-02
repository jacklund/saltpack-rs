use rmp_serde::decode;
use std::convert::From;

#[derive(Debug)]
pub enum Error {
    AuthenticationError(String),
    DecodeError(decode::Error),
    DecryptionError(String),
    IOError(std::io::Error),
    KeyLengthError(String),
    ValidationError(String),
}

impl From<decode::Error> for Error {
    fn from(e: decode::Error) -> Self {
        Error::DecodeError(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IOError(e)
    }
}
