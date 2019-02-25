use crate::encryption::EncryptionHeader;
use crate::error::Error;
use crate::keys::{PublicKey, SecretKey};
use crate::signcryption_header::SigncryptionHeader;
use crate::signing_header::SigningHeader;
use byteorder::{BigEndian, WriteBytesExt};
use rmp::decode;
use rmp_serde;
use rmp_serde::Deserializer;
use serde::Deserialize;
use serde_repr::{Deserialize_repr, Serialize_repr};
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

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Mode::EncryptionMode => writeln!(f, "encryption"),
            Mode::AttachedSigningMode => writeln!(f, "attached signing"),
            Mode::DetachedSigningMode => writeln!(f, "detached signing"),
            Mode::SigncryptionMode => writeln!(f, "signcryption"),
        }?;

        Ok(())
    }
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
    pub fn decode(mut data: &[u8]) -> Result<(hash::Digest, Self), Error> {
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

pub fn create_sender_secretbox(sender: &PublicKey, payload_key: &[u8]) -> Vec<u8> {
    let nonce: secretbox::Nonce =
        secretbox::Nonce::from_slice(b"saltpack_sender_key_sbox").unwrap();
    let key = secretbox::Key::from_slice(&payload_key).unwrap();
    secretbox::seal(sender.as_ref(), &nonce, &key)
}

pub fn open_sender_secretbox(secretbox: &[u8], payload_key: &[u8]) -> Result<PublicKey, Error> {
    let nonce: secretbox::Nonce =
        secretbox::Nonce::from_slice(b"saltpack_sender_key_sbox").unwrap();
    let key = secretbox::Key::from_slice(&payload_key).unwrap();
    if let Ok(sender_public_key) = secretbox::open(secretbox, &nonce, &secretbox::Key::from_slice(&payload_key).unwrap()) {
        return Ok(PublicKey::from_slice(&sender_public_key)?);
    }

    Err(Error::DecryptionError("Unable to decrypt sender secret box with payload key".to_string()))
}

pub fn generate_recipient_nonce(recipient_index: u64) -> Vec<u8> {
    let mut recipient_nonce = RECIPIENT_NONCE_PREFIX.to_vec();
    recipient_nonce
        .write_u64::<BigEndian>(recipient_index)
        .unwrap();

    recipient_nonce
}

pub fn decrypt_payload_key_for_recipient(
    public_key: &box_::PublicKey,
    secret_key: &SecretKey,
    payload_key_box_list: &[Vec<u8>],
) -> Result<Vec<u8>, Error> {
    // Precompute the shared secret
    let key: box_::PrecomputedKey = box_::precompute(
        &public_key,
        &box_::SecretKey::from_slice(secret_key.as_ref()).unwrap(),
    );

    // Try to open each payload key box in turn
    for (recipient_index, payload_key_box) in payload_key_box_list.iter().enumerate() {
        let nonce = generate_recipient_nonce(recipient_index as u64);
        if let Ok(payload_key) = box_::open_precomputed(
            &payload_key_box,
            &box_::Nonce::from_slice(&nonce).unwrap(),
            &key,
        ) {
            return Ok(payload_key);
        }
    }

    Err(Error::DecryptionError(
        "Unable to decrypt payload key from recipients list".to_string(),
    ))
}

pub fn encrypt_payload_key_for_recipient(
    recipient: &PublicKey,
    recipient_index: u64,
    payload_key: &[u8],
    secret_key: &box_::SecretKey,
) -> Vec<u8> {
    let recipient_nonce = generate_recipient_nonce(recipient_index);
    let public_key = box_::PublicKey::from_slice(recipient.as_ref()).unwrap();
    box_::seal(
        &payload_key,
        &box_::Nonce::from_slice(&recipient_nonce).unwrap(),
        &public_key,
        &secret_key,
    )
}
