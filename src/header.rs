use crate::encryption::EncryptionHeader;
use crate::keys::{PublicKey, SecretKey};
use crate::signcryption_header::SigncryptionHeader;
use crate::signing_header::SigningHeader;
use byteorder::{BigEndian, WriteBytesExt};
use rmp::decode;
use rmp_serde::Deserializer;
use rmp_serde;
use serde_repr::{Deserialize_repr, Serialize_repr};
use serde::Deserialize;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::hash;
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

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Header {
    Encryption(EncryptionHeader),
    Signing(SigningHeader),
    Signcryption(SigncryptionHeader),
}

impl Header {
    pub fn decode(mut data: &[u8]) -> Result<(hash::Digest, Self), rmp_serde::decode::Error> {
        let bin_header_len: usize = decode::read_bin_len(&mut data).unwrap() as usize;
        let bin_header: Vec<u8> = data[..(bin_header_len)].to_vec();
        let mut de = Deserializer::new(bin_header.as_slice());
        let digest: hash::Digest = hash::sha512::hash(&bin_header);
        let header: Header = Deserialize::deserialize(&mut de)?;
        Ok((digest, header))
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

pub fn create_sender_secretbox(sender: &SecretKey, payload_key: &[u8]) -> Vec<u8> {
    let nonce: secretbox::Nonce =
        secretbox::Nonce::from_slice(b"saltpack_sender_key_sbox").unwrap();
    let key = secretbox::Key::from_slice(&payload_key).unwrap();
    secretbox::seal(sender, &nonce, &key)
}

pub fn encrypt_payload_key_for_recipient(
    recipient: &PublicKey,
    recipient_index: u64,
    payload_key: &[u8],
    secret_key: &box_::SecretKey,
) -> Vec<u8> {
    let mut recipient_nonce = RECIPIENT_NONCE_PREFIX.to_vec();
    recipient_nonce
        .write_u64::<BigEndian>(recipient_index)
        .unwrap();
    let public_key = box_::PublicKey::from_slice(recipient).unwrap();
    box_::seal(
        &payload_key,
        &box_::Nonce::from_slice(&recipient_nonce).unwrap(),
        &public_key,
        &secret_key,
    )
}
