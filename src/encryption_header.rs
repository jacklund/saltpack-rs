use rmp_serde::Serializer;
use serde::Serialize;
use serde_bytes;

use crate::header::{
    create_sender_secretbox, encrypt_payload_key_for_recipient, Mode, FORMAT_NAME, VERSION,
};
use crate::keys::{PublicKey, SecretKey};
use crate::util::generate_random_key;
use base64;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::hash;
use std::fmt;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptionRecipientPair {
    public_key: Option<PublicKey>,
    #[serde(with = "serde_bytes")]
    payload_key_box: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EncryptionHeader {
    format_name: String,
    version: [u32; 2],
    mode: Mode,
    public_key: box_::PublicKey,
    #[serde(with = "serde_bytes")]
    sender_secretbox: Vec<u8>,
    recipients_list: Vec<EncryptionRecipientPair>,
}

impl EncryptionHeader {
    pub fn new(sender: &SecretKey, recipients: &[PublicKey]) -> Self {
        let payload_key: Vec<u8> = generate_random_key();

        // Generate ephemeral keypair
        let (public_key, secret_key) = box_::gen_keypair();

        // Create sender_secretbox
        let sender_secretbox = create_sender_secretbox(&sender, &payload_key);

        let mut index: u64 = 0;
        let mut recipients_list: Vec<EncryptionRecipientPair> = vec![];
        for recipient in recipients {
            let payload_key_box = encrypt_payload_key_for_recipient(
                &recipient,
                index,
                &payload_key,
                &public_key,
                &secret_key,
            );
            recipients_list.push(EncryptionRecipientPair {
                public_key: Some(recipient.clone()),
                payload_key_box,
            });
            index += 1;
        }

        EncryptionHeader {
            format_name: FORMAT_NAME.to_string(),
            version: VERSION,
            mode: Mode::EncryptionMode,
            public_key,
            sender_secretbox,
            recipients_list,
        }
    }

    pub fn generate_header_packet(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![];
        self.serialize(&mut Serializer::new(&mut buf)).unwrap();
        let digest: hash::Digest = hash::sha512::hash(&buf);
        digest.serialize(&mut Serializer::new(&mut buf)).unwrap();
        let mut packet: Vec<u8> = vec![];
        buf.serialize(&mut Serializer::new(&mut packet)).unwrap();
        packet
    }
}

impl fmt::Display for EncryptionHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Header:")?;
        writeln!(f, "  format: {}", self.format_name)?;
        writeln!(f, "  version: {}.{}", self.version[0], self.version[1])?;
        writeln!(f, "  mode: encryption")?;
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
                "    public key: {}",
                if recipient.public_key.is_none() {
                    "nil".to_string()
                } else {
                    base64::encode(&recipient.public_key.unwrap().0)
                }
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
