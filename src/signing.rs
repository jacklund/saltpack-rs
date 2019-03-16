use crate::cryptotypes::MacKey;
use crate::error::Error;
use crate::handler::Handler;
use crate::header::Mode;
use crate::keyring::KeyRing;
use base64;
use rmp_serde::Deserializer;
use serde::Deserialize;
use sodiumoxide::crypto::box_::PublicKey;
use sodiumoxide::crypto::hash;
use sodiumoxide::crypto::secretbox::Key as SymmetricKey;
use std::fmt;
use std::io::Read;

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct SigningHeader {
    format_name: String,
    version: [u32; 2],
    mode: Mode,
    sender_public_key: PublicKey,
    nonce: [u8; 32],
}

impl SigningHeader {
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut de = Deserializer::new(buf);
        Ok(Deserialize::deserialize(&mut de)?)
    }

    pub fn get_handler(
        &self,
        header_hash: hash::Digest,
        keyring: &KeyRing,
    ) -> Result<Box<Handler>, Error> {
        unimplemented!()
    }
}

impl fmt::Display for SigningHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Header:")?;
        writeln!(f, "  format: {}", self.format_name)?;
        writeln!(f, "  version: {}.{}", self.version[0], self.version[1])?;
        if self.mode == Mode::AttachedSigning {
            writeln!(f, "  mode: attached signing")?;
        } else {
            writeln!(f, "  mode: detached signing")?;
        }
        writeln!(
            f,
            "  sender_public key: {}",
            base64::encode(&self.sender_public_key)
        )?;
        writeln!(f, "  nonce: {}", base64::encode(&self.nonce))?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct SigningHandler {
    pub payload_key: SymmetricKey,
    pub sender_public_key: PublicKey,
    pub mac_key: MacKey,
    pub header_hash: hash::Digest,
}

impl SigningHandler {
    pub fn new(
        payload_key: SymmetricKey,
        sender_public_key: PublicKey,
        mac_key: MacKey,
        header_hash: hash::Digest,
    ) -> SigningHandler {
        SigningHandler {
            payload_key,
            sender_public_key,
            mac_key,
            header_hash,
        }
    }
}

impl Handler for SigningHandler {
    fn process_payload(&self, reader: &mut Read) -> Result<Vec<u8>, Error> {
        unimplemented!()
    }
}
