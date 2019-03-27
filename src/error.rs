use base_x;
use rmp::decode;
use std::convert::From;

#[derive(Debug)]
pub enum Error {
    AuthenticationError(String),
    Base62DecodeError(base_x::DecodeError),
    MsgPackDecodeError(Box<std::error::Error>),
    DecryptionError(String),
    IOError(std::io::Error),
    KeyLengthError(String),
    ResolverError(String),
    ValidationError(String),
}

// DecryptionError:
// No key found to decrypt payload key
// Payload decryption error
// Error decrypting sender public key
//
// AuthenticationError:
// Authenticators didn't match
// Signature mismatch
//
// KeyLengthError:

impl From<decode::ValueReadError> for Error {
    fn from(e: decode::ValueReadError) -> Self {
        Error::MsgPackDecodeError(Box::new(e))
    }
}

impl From<rmp_serde::decode::Error> for Error {
    fn from(e: rmp_serde::decode::Error) -> Self {
        Error::MsgPackDecodeError(Box::new(e))
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IOError(e)
    }
}

impl From<base_x::DecodeError> for Error {
    fn from(e: base_x::DecodeError) -> Self {
        Error::Base62DecodeError(e)
    }
}
