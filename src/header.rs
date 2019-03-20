use crate::encryption::EncryptionHeader;
use crate::error::Error;
use crate::handler::Handler;
use crate::keyring::KeyRing;
use crate::process_data::KeyResolver;
use crate::signcryption::SigncryptionHeader;
use crate::signing::SigningHeader;
use rmp::decode;
use rmp_serde;
use rmp_serde::Deserializer;
use serde::Deserialize;
use serde_repr::{Deserialize_repr, Serialize_repr};
use sodiumoxide::crypto::hash;
use std::fmt;
use std::io::Read;
use std::str;

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
    Encryption = 0,
    AttachedSigning = 1,
    DetachedSigning = 2,
    Signcryption = 3,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Mode::Encryption => writeln!(f, "encryption"),
            Mode::AttachedSigning => writeln!(f, "attached signing"),
            Mode::DetachedSigning => writeln!(f, "detached signing"),
            Mode::Signcryption => writeln!(f, "signcryption"),
        }?;

        Ok(())
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Header {
    Encryption(EncryptionHeader),
    Signing(SigningHeader),
    Signcryption(SigncryptionHeader),
}

// We decrypt the common header first to get the mode enum
// Normally, we should be able to use the structure of the header to figure out
// which it is, but the headers are too similar for serde to properly distinguish them
#[derive(Debug, Deserialize)]
pub struct CommonHeader {
    pub format_name: String,
    pub version: Version,
    pub mode: Mode,
}

impl CommonHeader {
    fn validate(&self) -> Result<(), Error> {
        if self.format_name != FORMAT_NAME {
            return Err(Error::ValidationError(format!(
                "Unknown format name {}",
                self.format_name
            )));
        }

        if self.version != VERSION {
            return Err(Error::ValidationError(format!(
                "Unknown version {}",
                self.version
            )));
        }

        Ok(())
    }
}

impl Header {
    // Decode the header
    pub fn decode(mut reader: &mut Read) -> Result<(hash::Digest, Self), Error> {
        // The header is double-encoded, so we read the length and grab the buffer to decode first
        let bin_header_len: usize = decode::read_bin_len(&mut reader).unwrap() as usize;
        let mut buf = vec![0u8; bin_header_len];
        reader.read_exact(&mut buf)?;

        // Calculate the header hash for use later
        let digest: hash::Digest = hash::sha512::hash(&buf);

        // We need to clone the buffer because we're decoding the common header first, then
        // re-decoding the full header in each decode method
        let tmpbuf = buf.clone();
        let mut de = Deserializer::new(tmpbuf.as_slice());
        let common: CommonHeader = Deserialize::deserialize(&mut de)?;
        common.validate()?;

        // Decode the full header
        de = Deserializer::new(buf.as_slice());
        let header: Header = match common.mode {
            Mode::Encryption => Header::Encryption(EncryptionHeader::decode(de)?),
            Mode::AttachedSigning | Mode::DetachedSigning => {
                Header::Signing(SigningHeader::decode(&buf)?)
            }
            Mode::Signcryption => Header::Signcryption(SigncryptionHeader::decode(&buf)?),
        };
        Ok((digest, header))
    }

    // Get the handler, which is used to decrypt the payload
    pub fn get_handler(
        &self,
        header_hash: hash::Digest,
        keyring: &KeyRing,
        resolver: KeyResolver,
    ) -> Result<Box<Handler>, Error> {
        match self {
            Header::Encryption(encryption_header) => {
                encryption_header.get_handler(header_hash, keyring)
            }
            Header::Signing(signing_header) => signing_header.get_handler(header_hash, keyring),
            Header::Signcryption(signcryption_header) => {
                signcryption_header.get_handler(header_hash, keyring, resolver)
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
