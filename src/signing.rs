use crate::cryptotypes::{MacKey, Nonce};
use crate::decrypt::{DecryptedResult, KeyResolver};
use crate::error::Error;
use crate::handler::Handler;
use crate::header::Mode;
use crate::keyring::KeyRing;
use base64;
use sodiumoxide::crypto::box_::PublicKey;
use sodiumoxide::crypto::hash;
use sodiumoxide::crypto::secretbox::Key as SymmetricKey;
use sodiumoxide::crypto::sign::PublicKey as PublicSigningKey;
use sodiumoxide::crypto::sign::SecretKey as SigningKey;
use std::fmt;
use std::io::Read;

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct SigningHeader {
    format_name: String,
    version: [u32; 2],
    mode: Mode,
    sender_public_key: PublicSigningKey,
    nonce: Nonce,
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

pub fn decrypt_payload(
    reader: &mut Read,
    header: &SigningHeader,
    header_hash: &hash::Digest,
    keyring: &KeyRing,
    resolver: KeyResolver,
) -> Result<DecryptedResult, Error> {
    unimplemented!()
}
