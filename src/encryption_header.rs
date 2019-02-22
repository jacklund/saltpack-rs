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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EncryptionRecipientPair {
    public_key: Option<PublicKey>,
    #[serde(with = "serde_bytes")]
    payload_key_box: Vec<u8>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct EncryptionHeader {
    pub format_name: String,
    pub version: [u32; 2],
    pub mode: Mode,
    pub public_key: box_::PublicKey,
    #[serde(with = "serde_bytes")]
    pub sender_secretbox: Vec<u8>,
    pub recipients_list: Vec<EncryptionRecipientPair>,
}

impl EncryptionHeader {
    pub fn new(sender: &SecretKey, recipients: &[PublicKey]) -> Self {
        let payload_key: Vec<u8> = generate_random_key();

        // Generate ephemeral keypair
        let (public_key, secret_key) = box_::gen_keypair();

        // Create sender_secretbox
        let sender_secretbox = create_sender_secretbox(&sender, &payload_key);

        let mut recipients_list: Vec<EncryptionRecipientPair> = vec![];
        for (index, recipient) in recipients.iter().enumerate() {
            let payload_key_box = encrypt_payload_key_for_recipient(
                &recipient,
                index as u64,
                &payload_key,
                &secret_key,
            );
            recipients_list.push(EncryptionRecipientPair {
                public_key: Some(*recipient),
                payload_key_box,
            });
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
        for (index, recipient) in self.recipients_list.iter().enumerate() {
            writeln!(f, "  recipient {}:", index)?;
            writeln!(
                f,
                "    public key: {}",
                if recipient.public_key.is_none() {
                    "nil".to_string()
                } else {
                    base64::encode(&recipient.public_key.unwrap())
                }
            )?;
            writeln!(
                f,
                "    payload key box: {}",
                base64::encode(&recipient.payload_key_box)
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::encryption_header::EncryptionHeader;
    use crate::header::Header;
    use crate::keys::{from_binary, PublicKey, SecretKey};
    use crate::util::{generate_random_key, read_base64_file};
    use rmp::decode;
    use rmp_serde::{Deserializer, Serializer};
    use serde::{Deserialize, Serialize};
    use std::io::Cursor;

    #[test]
    fn test_serialize_deserialize_encryption_header() {
        let sender: SecretKey = from_binary(&generate_random_key()).unwrap();
        let mut recipients: Vec<PublicKey> = vec![];
        for _ in 0..4 {
            recipients.push(from_binary(&generate_random_key()).unwrap());
        }

        let header: EncryptionHeader = EncryptionHeader::new(&sender, &recipients);

        let mut buf: Vec<u8> = vec![];
        header.serialize(&mut Serializer::new(&mut buf)).unwrap();
        let mut de = Deserializer::new(&buf[..]);
        let foo: EncryptionHeader = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(header, foo);
    }

    #[test]
    fn test_read_encryption_header() {
        let data: Vec<u8> = read_base64_file("fixtures/encryption.txt");
        let bin_header_len: usize = decode::read_bin_len(&mut data.as_slice()).unwrap() as usize;
        let bin_header: Vec<u8> = data[3..(bin_header_len + 3)].to_vec();
        let cur = Cursor::new(&bin_header[..]);
        let mut de = Deserializer::new(cur);
        let header: Header = Deserialize::deserialize(&mut de).unwrap();
        if let Header::Encryption(encryption_header) = header {
            assert_eq!(14, encryption_header.recipients_list.len());
        } else {
            assert!(false);
        }
    }
}
