use crate::encryption;
use crate::error::Error;
use crate::handler::Handler;
use crate::cryptotypes::{FromSlice, Nonce, PublicKey, SecretKey, SymmetricKey};
use crate::keyring::KeyRing;
use crate::signcryption::SigncryptionHeader;
use crate::signing::SigningHeader;
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
use std::io::Read;

pub const FORMAT_NAME: &str = "saltpack";
pub const VERSION: Version = Version(2, 0);

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Version(u32, u32);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{}.{}", self.0, self.1)
    }
}

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
    Encryption(encryption::EncryptionHeader),
    Signing(SigningHeader),
    Signcryption(SigncryptionHeader),
}

impl Header {
    pub fn decode(mut reader: &mut Read) -> Result<(hash::Digest, Self), Error> {
        let bin_header_len: usize = decode::read_bin_len(&mut reader).unwrap() as usize;
        println!("header len = {}", bin_header_len);
        let mut buf = vec![0u8; bin_header_len];
        reader.read_exact(&mut buf)?;
        println!("header data length = {}", buf.len());
        println!("header data = {:x?}", buf);
        let digest: hash::Digest = hash::sha512::hash(&buf);
        let mut de = Deserializer::new(buf.as_slice());
        let header: Header = Deserialize::deserialize(&mut de)?;
        Ok((digest, header))
    }

    pub fn get_handler(&self, header_hash: hash::Digest, keyring: &KeyRing) -> Result<Box<Handler>, Error> {
        match self {
            Header::Encryption(encryption_header) => encryption_header.get_handler(header_hash, keyring),
            Header::Signing(signing_header) => signing_header.get_handler(header_hash, keyring),
            Header::Signcryption(signcryption_header) => signcryption_header.get_handler(header_hash, keyring),
        }
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

pub fn create_sender_secretbox(sender: &PublicKey, payload_key: &SymmetricKey) -> Vec<u8> {
    let nonce: secretbox::Nonce =
        secretbox::Nonce::from_slice(b"saltpack_sender_key_sbox").unwrap();
    secretbox::seal(sender.as_ref(), &nonce, &payload_key.into())
}

pub fn open_sender_secretbox(
    secretbox: &[u8],
    payload_key: &SymmetricKey,
) -> Result<PublicKey, Error> {
    let nonce: secretbox::Nonce =
        secretbox::Nonce::from_slice(b"saltpack_sender_key_sbox").unwrap();
    if let Ok(sender_public_key) =
        secretbox::open(secretbox, &nonce, &payload_key.into())
    {
        return Ok(PublicKey::from_slice(&sender_public_key)?);
    }

    Err(Error::DecryptionError(
        "Unable to decrypt sender secret box with payload key".to_string(),
    ))
}

pub fn generate_recipient_nonce(recipient_index: u64) -> Nonce {
    let mut recipient_nonce = RECIPIENT_NONCE_PREFIX.to_vec();
    recipient_nonce
        .write_u64::<BigEndian>(recipient_index)
        .unwrap();

    Nonce::from_slice(&recipient_nonce).unwrap()
}

pub fn decrypt_payload_key_for_recipient(
    public_key: &box_::PublicKey,
    secret_key: &SecretKey,
    payload_key_box_list: &[Vec<u8>],
) -> Option<Vec<u8>> {
    // Precompute the shared secret
    let key: box_::PrecomputedKey = box_::precompute(
        &public_key,
        &secret_key.clone().into(),
    );

    // Try to open each payload key box in turn
    for (recipient_index, payload_key_box) in payload_key_box_list.iter().enumerate() {
        let nonce = generate_recipient_nonce(recipient_index as u64);
        if let Ok(payload_key) = box_::open_precomputed(
            &payload_key_box,
            &nonce.into(),
            &key,
        ) {
            return Some(payload_key);
        }
    }

    None
}

pub fn encrypt_payload_key_for_recipient(
    recipient: &PublicKey,
    recipient_index: u64,
    payload_key: &SymmetricKey,
    secret_key: &box_::SecretKey,
) -> Vec<u8> {
    let recipient_nonce = generate_recipient_nonce(recipient_index);
    box_::seal(
        &payload_key.bytes(),
        &recipient_nonce.into(),
        &recipient.clone().into(),
        &secret_key,
    )
}
