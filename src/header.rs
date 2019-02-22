use crate::encryption_header::EncryptionHeader;
use crate::keys::{PublicKey, SecretKey};
use crate::signcryption_header::SigncryptionHeader;
use crate::signing_header::SigningHeader;
use byteorder::{BigEndian, WriteBytesExt};
use serde_repr::{Deserialize_repr, Serialize_repr};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::secretbox;
use std::fmt;

pub const FORMAT_NAME: &str = "saltpack";
pub const VERSION: [u32; 2] = [2, 0];

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug)]
#[repr(u8)]
pub enum Mode {
    EncryptionMode = 0,
    AttachedSigningMode = 1,
    DetachedSigningMode = 2,
    SigncryptionMode = 3,
}

const RECIPIENT_NONCE_PREFIX: &[u8] = b"saltpack_recipsb";

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Header {
    Encryption(EncryptionHeader),
    Signing(SigningHeader),
    Signcryption(SigncryptionHeader),
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

pub fn create_sender_secretbox(sender: &SecretKey, payload_key: &[u8]) -> Vec<u8> {
    let nonce: secretbox::Nonce =
        secretbox::Nonce::from_slice(b"saltpack_sender_key_sbox").unwrap();
    let key = secretbox::Key::from_slice(&payload_key).unwrap();
    secretbox::seal(&sender.0, &nonce, &key)
}

pub fn encrypt_payload_key_for_recipient(
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

        let header: EncryptionHeader = EncryptionHeader::new(&sender, &recipients);
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
