use crate::cryptotypes::{FromSlice, Nonce, SigningNonce, SIGNING_NONCE_SIZE};
use base64;
use byteorder::{BigEndian, WriteBytesExt};
use rand;
use rmp::encode;
use rmp_serde::Serializer;
use serde::Serialize;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey, PUBLICKEYBYTES};
use sodiumoxide::crypto::secretbox::Key as SymmetricKey;
use sodiumoxide::crypto::secretbox::KEYBYTES as SYMMETRIC_KEY_BYTES;
use sodiumoxide::crypto::sign::PublicKey as PublicSigningKey;
use sodiumoxide::crypto::sign::SecretKey as SigningKey;
use sodiumoxide::crypto::sign::SECRETKEYBYTES as SIGNING_KEY_BYTES;
use sodiumoxide::crypto::{box_, hash, sign};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::iter;

pub fn generate_random_public_key() -> PublicKey {
    PublicKey::from_slice(&generate_random_data(PUBLICKEYBYTES)).unwrap()
}

pub fn generate_random_symmetric_key() -> SymmetricKey {
    SymmetricKey::from_slice(&generate_random_data(SYMMETRIC_KEY_BYTES)).unwrap()
}

pub fn generate_random_signing_nonce() -> SigningNonce {
    SigningNonce::from_slice(&generate_random_data(SIGNING_NONCE_SIZE)).unwrap()
}

pub fn generate_random_signing_key() -> SigningKey {
    SigningKey::from_slice(&generate_random_data(SIGNING_KEY_BYTES)).unwrap()
}

pub fn generate_random_data(len: usize) -> Vec<u8> {
    iter::repeat_with(rand::random::<u8>)
        .take(len)
        .collect::<Vec<u8>>()
}

pub fn generate_keypair() -> (PublicKey, SecretKey) {
    box_::gen_keypair()
}

pub fn generate_signing_keypair() -> (PublicSigningKey, SigningKey) {
    sign::gen_keypair()
}

pub fn read_signing_keys_and_data(
    filename: &str,
) -> (PublicKey, SecretKey, PublicSigningKey, SigningKey, Vec<u8>) {
    let mut data: Vec<u8> = vec![];
    let mut public_key_bytes: Vec<u8> = vec![];
    let mut private_key_bytes: Vec<u8> = vec![];
    let mut signing_key_bytes: Vec<u8> = vec![];
    let mut public_signing_key_bytes: Vec<u8> = vec![];
    for line in BufReader::new(File::open(filename).unwrap()).lines() {
        if public_key_bytes.is_empty() {
            public_key_bytes = base64::decode(&line.unwrap()).unwrap();
        } else if private_key_bytes.is_empty() {
            private_key_bytes = base64::decode(&line.unwrap()).unwrap();
        } else if public_signing_key_bytes.is_empty() {
            public_signing_key_bytes = base64::decode(&line.unwrap()).unwrap();
        } else if signing_key_bytes.is_empty() {
            signing_key_bytes = base64::decode(&line.unwrap()).unwrap();
        } else {
            data.append(&mut base64::decode(&line.unwrap()).unwrap());
        }
    }

    (
        PublicKey::from_slice(&public_key_bytes).unwrap(),
        SecretKey::from_slice(&private_key_bytes).unwrap(),
        PublicSigningKey::from_slice(&public_key_bytes).unwrap(),
        SigningKey::from_slice(&signing_key_bytes).unwrap(),
        data,
    )
}

pub fn read_base64_file(filename: &str) -> Vec<u8> {
    let mut data: Vec<u8> = vec![];
    for line in BufReader::new(File::open(filename).unwrap()).lines() {
        data.append(&mut base64::decode(&line.unwrap()).unwrap());
    }

    data
}

pub fn cryptobox_zero_bytes(
    nonce: &Nonce,
    public_key: &PublicKey,
    secret_key: &SecretKey,
) -> Vec<u8> {
    let zero_bytes: Vec<u8> = iter::repeat(0u8).take(32).collect();
    box_::seal(&zero_bytes, &nonce.into(), &public_key, &secret_key)
}

pub const RECIPIENT_NONCE_PREFIX: &[u8] = b"saltpack_recipsb";

pub fn generate_recipient_nonce(recipient_index: u64) -> Nonce {
    let mut recipient_nonce = RECIPIENT_NONCE_PREFIX.to_vec();
    recipient_nonce
        .write_u64::<BigEndian>(recipient_index)
        .unwrap();

    Nonce::from_slice(&recipient_nonce).unwrap()
}

// Serialize the packet, generate the hash of the serialized packet,
// then re-encode the serialized packet as a msgpack bin object
pub fn generate_header_packet<T>(header: &T) -> (hash::Digest, Vec<u8>)
where
    T: Serialize,
{
    let mut buf: Vec<u8> = vec![];
    header.serialize(&mut Serializer::new(&mut buf)).unwrap();
    let digest: hash::Digest = hash::sha512::hash(&buf);
    let mut packet: Vec<u8> = vec![];
    encode::write_bin(&mut packet, &buf).unwrap();
    (digest, packet)
}
