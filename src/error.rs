use base_x;
use rmp::decode;
use rmp_serde::encode;
use std::convert::From;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    AuthenticationError(String),
    Base62DecodeError(base_x::DecodeError),
    DecryptionError(String),
    IOError(std::io::Error),
    KeyLengthError(usize, usize),
    MsgPackDecodeError(Box<std::error::Error>),
    MsgPackEncodeError(encode::Error),
    ResolverError(String),
    ValidationError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::AuthenticationError(msg) => write!(f, "Authentication error: {}", msg),
            Error::Base62DecodeError(e) => write!(f, "Error decoding Base62: {}", e),
            Error::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
            Error::IOError(e) => write!(f, "IO Error: {}", e),
            Error::KeyLengthError(expected, actual) => write!(
                f,
                "Key length error. Expected key of length {}, but found {}",
                expected, actual
            ),
            Error::MsgPackDecodeError(e) => write!(f, "Error decoding msgpack: {}", e),
            Error::MsgPackEncodeError(e) => write!(f, "Error encoding msgpack: {}", e),
            Error::ResolverError(msg) => write!(f, "Resolver error: {}", msg),
            Error::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
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

impl From<encode::Error> for Error {
    fn from(e: encode::Error) -> Self {
        Error::MsgPackEncodeError(e)
    }
}
