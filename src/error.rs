use base_x;
use rmp_serde::decode;
use std::convert::From;

#[derive(Debug)]
pub enum Error {
    AuthenticationError(String),
    Base62DecodeError(String),
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

impl From<base_x::DecodeError> for Error {
    fn from(e: base_x::DecodeError) -> Self {
        Error::Base62DecodeError(e.to_string())
    }
}
