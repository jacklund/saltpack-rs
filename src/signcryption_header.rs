use serde_bytes;

use crate::header::{
    create_sender_secretbox, encrypt_payload_key_for_recipient, Mode, FORMAT_NAME, VERSION,
};
use base64;
use sodiumoxide::crypto::box_;
use std::fmt;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SigncryptionRecipientPair {
    #[serde(with = "serde_bytes")]
    recipient_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    payload_key_box: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SigncryptionHeader {
    format_name: String,
    version: [u32; 2],
    mode: Mode,
    public_key: box_::PublicKey,
    #[serde(with = "serde_bytes")]
    sender_secretbox: Vec<u8>,
    recipients_list: Vec<SigncryptionRecipientPair>,
}

impl fmt::Display for SigncryptionHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Header:")?;
        writeln!(f, "  format: {}", self.format_name)?;
        writeln!(f, "  version: {}.{}", self.version[0], self.version[1])?;
        writeln!(f, "  mode: signcryption")?;
        writeln!(f, "  public key: {}", base64::encode(&self.public_key))?;
        writeln!(
            f,
            "  sender secretbox: {}",
            base64::encode(&self.sender_secretbox)
        )?;
        let mut index = 0;
        for recipient in self.recipients_list.clone() {
            writeln!(f, "  recipient {}:", index)?;
            writeln!(
                f,
                "    recipient id: {}",
                base64::encode(&recipient.recipient_id)
            )?;
            writeln!(
                f,
                "    payload key box: {}",
                base64::encode(&recipient.payload_key_box)
            )?;
            index += 1;
        }

        Ok(())
    }
}
