use crate::encrypt;
use crate::error::Error;
use crate::header::{parse_header, Header};
use crate::keyring::KeyRing;
use crate::signcrypt;

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

pub fn decrypt(
    reader: &mut Read,
    keyring: &KeyRing,
    key_resolver: KeyResolver,
) -> Result<DecryptedResult, Error> {
    let (header, header_hash) = parse_header(reader)?;
    match header {
        Header::Encryption(encryption_header) => {
            encrypt::decrypt_payload(reader, &encryption_header, &header_hash, keyring)
        }
        Header::Signcryption(signecryption_header) => signcrypt::decrypt_payload(
            reader,
            &signecryption_header,
            &header_hash,
            keyring,
            key_resolver,
        ),
        Header::Signing(signing_header) => Err(Error::DecryptionError(format!(
            "Error attempting to decrypt message of type '{}'",
            signing_header.mode
        ))),
    }
}
