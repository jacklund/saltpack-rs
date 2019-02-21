use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use serde_bytes;

use crate::keys::{PublicKey, SecretKey};
use crate::util::generate_random_key;
use base64;
use byteorder::{BigEndian, WriteBytesExt};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::hash;
use sodiumoxide::crypto::secretbox;
use std::fmt;

const FORMAT_NAME: &str = "saltpack";
const VERSION: [u32; 2] = [2, 0];

// For use of 'serde_bytes' below, see https://github.com/3Hren/msgpack-rust/issues/163
//
// Open questions:
//   1. How do you encrypt the payload key if the recipient has no public key, i.e. is anonymous
//   2. Why, when I encrypt something for someone with no PGP public key, does it give me a header
//      with 15 recipients? (see fixtures/test.txt)

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptionRecipientPair {
    public_key: Option<PublicKey>,
    #[serde(with = "serde_bytes")]
    payload_key_box: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SigncryptionRecipientPair {
    #[serde(with = "serde_bytes")]
    recipient_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    payload_key_box: Vec<u8>,
}

pub const ENCRYPTION_MODE: u8 = 0;
pub const ATTACHED_SIGNING_MODE: u8 = 1;
pub const DETACHED_SIGNING_MODE: u8 = 2;
pub const SIGNCRYPTION_MODE: u8 = 3;

#[derive(Debug, Deserialize, Serialize)]
pub struct EncryptionHeader {
    format_name: String,
    version: [u32; 2],
    mode: u8,
    public_key: box_::PublicKey,
    #[serde(with = "serde_bytes")]
    sender_secretbox: Vec<u8>,
    recipients_list: Vec<EncryptionRecipientPair>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SigncryptionHeader {
    format_name: String,
    version: [u32; 2],
    mode: u8,
    public_key: box_::PublicKey,
    #[serde(with = "serde_bytes")]
    sender_secretbox: Vec<u8>,
    recipients_list: Vec<SigncryptionRecipientPair>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SigningHeader {
    format_name: String,
    version: [u32; 2],
    mode: u8,
    sender_public_key: box_::PublicKey,
    nonce: [u8; 32],
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Header {
    Encryption(EncryptionHeader),
    Signing(SigningHeader),
    Signcryption(SigncryptionHeader),
}

impl EncryptionHeader {
    pub fn new(sender: &SecretKey, recipients: &[PublicKey], mode: u8) -> Self {
        let payload_key: Vec<u8> = generate_random_key();

        // Generate ephemeral keypair
        let public_key: box_::PublicKey;
        let secret_key: box_::SecretKey;
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
            mode,
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
        match self.mode {
            ENCRYPTION_MODE => writeln!(f, "  mode: encryption"),
            ATTACHED_SIGNING_MODE => writeln!(f, "  mode: attached signing"),
            DETACHED_SIGNING_MODE => writeln!(f, "  mode: detached signing"),
            SIGNCRYPTION_MODE => writeln!(f, "  mode: signcryption"),
            _ => writeln!(f, "  mode: unknown({})", self.mode),
        }?;
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

impl fmt::Display for SigningHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Header:")?;
        writeln!(f, "  format: {}", self.format_name)?;
        writeln!(f, "  version: {}.{}", self.version[0], self.version[1])?;
        match self.mode {
            ENCRYPTION_MODE => writeln!(f, "  mode: encryption"),
            ATTACHED_SIGNING_MODE => writeln!(f, "  mode: attached signing"),
            DETACHED_SIGNING_MODE => writeln!(f, "  mode: detached signing"),
            SIGNCRYPTION_MODE => writeln!(f, "  mode: signcryption"),
            _ => writeln!(f, "  mode: unknown({})", self.mode),
        }?;
        writeln!(
            f,
            "  sender_public key: {}",
            base64::encode(&self.sender_public_key)
        )?;
        writeln!(f, "  nonce: {}", base64::encode(&self.nonce))?;

        Ok(())
    }
}

impl fmt::Display for SigncryptionHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Header:")?;
        writeln!(f, "  format: {}", self.format_name)?;
        writeln!(f, "  version: {}.{}", self.version[0], self.version[1])?;
        match self.mode {
            ENCRYPTION_MODE => writeln!(f, "  mode: encryption"),
            ATTACHED_SIGNING_MODE => writeln!(f, "  mode: attached signing"),
            DETACHED_SIGNING_MODE => writeln!(f, "  mode: detached signing"),
            SIGNCRYPTION_MODE => writeln!(f, "  mode: signcryption"),
            _ => writeln!(f, "  mode: unknown({})", self.mode),
        }?;
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

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Header::Encryption(hdr) => hdr.fmt(f),
            Header::Signing(hdr) => hdr.fmt(f),
            Header::Signcryption(hdr) => hdr.fmt(f),
        }
    }
}

fn create_sender_secretbox(sender: &SecretKey, payload_key: &[u8]) -> Vec<u8> {
    let nonce: secretbox::Nonce =
        secretbox::Nonce::from_slice(b"saltpack_sender_key_sbox").unwrap();
    let key = secretbox::Key::from_slice(&payload_key).unwrap();
    secretbox::seal(&sender.0, &nonce, &key)
}

const RECIPIENT_NONCE_PREFIX: &[u8] = b"saltpack_recipsb";

fn encrypt_payload_key_for_recipient(
    recipient: &PublicKey,
    recipient_index: u64,
    payload_key: &[u8],
    public_key: &box_::PublicKey,
    secret_key: &box_::SecretKey,
) -> Vec<u8> {
    let mut recipient_nonce = RECIPIENT_NONCE_PREFIX.to_vec();
    recipient_nonce
        .write_u64::<BigEndian>(recipient_index)
        .unwrap();
    let public_key = box_::PublicKey::from_slice(&recipient.0).unwrap();
    box_::seal(
        &payload_key,
        &box_::Nonce::from_slice(&recipient_nonce).unwrap(),
        &public_key,
        &secret_key,
    )
}

#[cfg(test)]
mod tests {
    use crate::header::ENCRYPTION_MODE;
    use crate::header::{EncryptionHeader, Header};
    use crate::keys::{PublicKey, SecretKey};
    use crate::util::{generate_random_key, read_base64_file};
    use rmp::decode;
    use rmp_serde::{Deserializer, Serializer};
    use serde::{Deserialize, Serialize};
    use serde_bytes;
    use sodiumoxide::crypto::box_;
    use std::io::Cursor;

    #[test]
    fn test_encryption_header() {
        let sender: SecretKey = SecretKey::from_binary(&generate_random_key()).unwrap();
        let mut recipients: Vec<PublicKey> = vec![];
        for _ in 0..4 {
            recipients.push(PublicKey::from_binary(&generate_random_key()).unwrap());
        }

        let header: EncryptionHeader = EncryptionHeader::new(&sender, &recipients, ENCRYPTION_MODE);
        let mut buf: Vec<u8> = vec![];
        header.serialize(&mut Serializer::new(&mut buf)).unwrap();
        println!("{:x?}", buf);
        let mut de = Deserializer::new(&buf[..]);
        let foo: EncryptionHeader = Deserialize::deserialize(&mut de).unwrap();
        println!("{:?}", foo);
        assert!(false);
    }

    #[test]
    fn test_read_encryption_header() {
        let data: Vec<u8> = read_base64_file("fixtures/test.txt");
        let bin_header_len: usize = decode::read_bin_len(&mut data.as_slice()).unwrap() as usize;
        let bin_header: Vec<u8> = data[3..(bin_header_len + 3)].to_vec();
        let cur = Cursor::new(&bin_header[..]);
        let mut de = Deserializer::new(cur);
        let foo: Header = Deserialize::deserialize(&mut de).unwrap();
        println!("{}", foo);
        assert!(false);
    }

    #[test]
    fn test_read_signcryption_header() {
        let data: Vec<u8> = read_base64_file("fixtures/test2.txt");
        let bin_header_len: usize = decode::read_bin_len(&mut data.as_slice()).unwrap() as usize;
        let bin_header: Vec<u8> = data[3..(bin_header_len + 3)].to_vec();
        let cur = Cursor::new(&bin_header[..]);
        let mut de = Deserializer::new(cur);
        let foo: Header = Deserialize::deserialize(&mut de).unwrap();
        println!("{}", foo);
        assert!(false);
    }

    #[test]
    fn test_read_struct() {
        #[derive(Debug, Deserialize)]
        struct Test {
            #[serde(with = "serde_bytes")]
            data: Vec<u8>,
        }

        let buf = [
            0x91, 0xc4, 0x30, 0x6, 0xdf, 0x77, 0xd, 0x70, 0x30, 0x2c, 0x64, 0xa1, 0xca, 0xde, 0xba,
            0xc9, 0x10, 0xaf, 0xfe, 0x34, 0xe7, 0x65, 0xe0, 0xd2, 0x46, 0x35, 0xa7, 0x59, 0x4a,
            0x15, 0x7, 0x99, 0x2b, 0x81, 0x30, 0x87, 0x92, 0x34, 0xf9, 0x7d, 0x44, 0x87, 0xb4,
            0xbf, 0x1f, 0xf0, 0x3c, 0x3b, 0xd5, 0x71, 0xf5,
        ];
        let cur = Cursor::new(&buf[..]);
        let mut de = Deserializer::new(cur);
        let decoded: Test = Deserialize::deserialize(&mut de).unwrap();

        println!("{:?}", decoded);
        assert!(false);
    }
}
