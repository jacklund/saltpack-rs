use crate::error::Error;
use crate::handler::Handler;
use crate::header::Mode;
use crate::cryptotypes::{MacKey, PublicKey, SymmetricKey};
use crate::keyring::KeyRing;
use base64;
use sodiumoxide::crypto::{box_, hash};
use std::fmt;
use std::io::Read;

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct SigningHeader {
    format_name: String,
    version: [u32; 2],
    mode: Mode,
    sender_public_key: box_::PublicKey,
    nonce: [u8; 32],
}

impl SigningHeader {
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
        if self.mode == Mode::AttachedSigningMode {
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
