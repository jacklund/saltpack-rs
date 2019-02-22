use crate::header::{
    create_sender_secretbox, encrypt_payload_key_for_recipient, Mode, FORMAT_NAME, VERSION,
};
use base64;
use sodiumoxide::crypto::box_;
use std::fmt;

#[derive(Debug, Deserialize, Serialize)]
pub struct SigningHeader {
    format_name: String,
    version: [u32; 2],
    mode: Mode,
    sender_public_key: box_::PublicKey,
    nonce: [u8; 32],
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
