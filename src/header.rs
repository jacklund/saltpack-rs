use crate::encryption;
use crate::error::Error;
use crate::handler::Handler;
use crate::cryptotypes::{FromSlice, Nonce, PublicKey, SecretKey, SymmetricKey};
use crate::keyring::KeyRing;
use crate::signcryption::SigncryptionHeader;
use crate::signing::SigningHeader;
use byteorder::{BigEndian, WriteBytesExt};
use rmp::decode;
use rmp_serde;
use rmp_serde::Deserializer;
use serde::Deserialize;
use serde_repr::{Deserialize_repr, Serialize_repr};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::hash;
use sodiumoxide::crypto::secretbox;
use std::fmt;
use std::io::Read;

pub const FORMAT_NAME: &str = "saltpack";
pub const VERSION: Version = Version(2, 0);

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Version(u32, u32);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{}.{}", self.0, self.1)
    }
}

#[derive(Clone, Serialize_repr, Deserialize_repr, PartialEq, Debug)]
#[repr(u8)]
pub enum Mode {
    EncryptionMode = 0,
    AttachedSigningMode = 1,
    DetachedSigningMode = 2,
    SigncryptionMode = 3,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Mode::EncryptionMode => writeln!(f, "encryption"),
            Mode::AttachedSigningMode => writeln!(f, "attached signing"),
            Mode::DetachedSigningMode => writeln!(f, "detached signing"),
            Mode::SigncryptionMode => writeln!(f, "signcryption"),
        }?;

        Ok(())
    }
}

pub const RECIPIENT_NONCE_PREFIX: &[u8] = b"saltpack_recipsb";

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Header {
    Encryption(encryption::EncryptionHeader),
    Signing(SigningHeader),
    Signcryption(SigncryptionHeader),
}

impl Header {
    pub fn decode(mut reader: &mut Read) -> Result<(hash::Digest, Self), Error> {
        let bin_header_len: usize = decode::read_bin_len(&mut reader).unwrap() as usize;
        println!("header len = {}", bin_header_len);
        let mut buf = vec![0u8; bin_header_len];
        reader.read_exact(&mut buf)?;
        println!("header data length = {}", buf.len());
        println!("header data = {:x?}", buf);
        let digest: hash::Digest = hash::sha512::hash(&buf);
        let mut de = Deserializer::new(buf.as_slice());
        let header: Header = Deserialize::deserialize(&mut de)?;
        Ok((digest, header))
    }

    pub fn get_handler(&self, header_hash: hash::Digest, keyring: &KeyRing) -> Result<Box<Handler>, Error> {
        match self {
            Header::Encryption(encryption_header) => encryption_header.get_handler(header_hash, keyring),
            Header::Signing(signing_header) => signing_header.get_handler(header_hash, keyring),
            Header::Signcryption(signcryption_header) => signcryption_header.get_handler(header_hash, keyring),
        }
    }
}

pub trait HeaderBoilerplate {
    fn validate(&self) -> Result<(), Error>;
}

macro_rules! boilerplate {
    ( $name:ident, $mode:ident ) => {
        impl HeaderBoilerplate for $name {
            fn validate(&self) -> Result<(), Error> {
                if self.format_name != FORMAT_NAME {
                    return Err(Error::ValidationError(format!(
                        "Unknown format name '{}'",
                        self.format_name
                    )));
                }

                if self.version != VERSION {
                    return Err(Error::ValidationError(format!(
                        "Unknown version '{}'",
                        self.version
                    )));
                }

                if self.mode != Mode::$mode {
                    return Err(Error::ValidationError(format!(
                        "Incorrect mode '{}'",
                        self.mode
                    )));
                }

                Ok(())
            }
        }
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Header::Encryption(hdr) => hdr.fmt(f),
            Header::Signing(hdr) => hdr.fmt(f),
            Header::Signcryption(hdr) => hdr.fmt(f),
        }
    }
}
