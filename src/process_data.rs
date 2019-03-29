use crate::error::Error;
use crate::header::Header;
use crate::keyring::KeyRing;

use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
use sodiumoxide::crypto::secretbox::Key as SymmetricKey;
use sodiumoxide::crypto::sign::PublicKey as PublicSigningKey;
use std::io::Read;

pub type KeyResolver = fn(&Vec<Vec<u8>>) -> Result<Vec<Option<SymmetricKey>>, Error>;

#[derive(Clone, Debug)]
pub struct MessageKeyInfo {
    pub sender_public_key: Option<PublicKey>,
    pub receiver_private_key: Option<SecretKey>,
    pub named_receivers: Vec<Vec<u8>>,
    pub num_anon_receivers: usize,
}

pub enum DecryptedResult {
    Encryption {
        plaintext: Vec<u8>,
        mki: MessageKeyInfo,
    },
    SignCryption {
        plaintext: Vec<u8>,
        sender_public_key: PublicSigningKey,
    },
}

pub fn process_data<'a>(
    reader: &mut Read,
    keyring: &KeyRing,
    key_resolver: KeyResolver,
) -> Result<DecryptedResult, Error> {
    let (header_hash, header) = Header::decode(reader)?;
    let handler = header.get_handler(header_hash, keyring, key_resolver)?;
    handler.process_payload(reader)
}
