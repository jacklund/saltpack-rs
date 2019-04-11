use crate::encrypt;
use crate::error::Error;
use crate::header::{CommonHeader, Header, Mode};
use crate::keyring::KeyRing;
use crate::signcrypt;
use crate::signing;

use rmp::decode;
use rmp_serde::Deserializer;
use serde::Deserialize;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
use sodiumoxide::crypto::hash;
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
        Header::Signing(signing_header) => {
            signing::decrypt_payload(reader, &signing_header, &header_hash, keyring, key_resolver)
        }
    }
}

// Decode the header
pub fn parse_header(mut reader: &mut Read) -> Result<(Header, hash::Digest), Error> {
    // The header is double-encoded, so we read the length and grab the buffer to decode first
    let bin_header_len: usize = decode::read_bin_len(&mut reader)? as usize;
    let mut buf = vec![0u8; bin_header_len];
    reader.read_exact(&mut buf)?;

    // Calculate the header hash for use later
    let digest: hash::Digest = hash::sha512::hash(&buf);

    // We need to clone the buffer because we're decoding the common header first, then
    // re-decoding the full header in each decode method
    let tmpbuf = buf.clone();
    let mut de = Deserializer::new(tmpbuf.as_slice());
    let common: CommonHeader = Deserialize::deserialize(&mut de)?;
    common.validate()?;

    // Decode the full header
    de = Deserializer::new(buf.as_slice());
    let header: Header = match common.mode {
        Mode::Encryption => Header::Encryption(Deserialize::deserialize(&mut de)?),
        Mode::AttachedSigning | Mode::DetachedSigning => {
            Header::Signing(Deserialize::deserialize(&mut de)?)
        }
        Mode::Signcryption => Header::Signcryption(Deserialize::deserialize(&mut de)?),
    };
    Ok((header, digest))
}
