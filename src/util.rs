use crate::cryptotypes::{FromSlice, Nonce};
use base64;
use byteorder::{BigEndian, WriteBytesExt};
use rand;
use rmp::encode;
use rmp_serde::Serializer;
use serde::Serialize;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
use sodiumoxide::crypto::secretbox::Key as SymmetricKey;
use sodiumoxide::crypto::{box_, hash};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::iter;

pub fn generate_random_public_key() -> PublicKey {
    PublicKey::from_slice(&generate_random_key()).unwrap()
}

pub fn generate_random_symmetric_key() -> SymmetricKey {
    SymmetricKey::from_slice(&generate_random_key()).unwrap()
}

fn generate_random_key() -> Vec<u8> {
    iter::repeat_with(rand::random::<u8>)
        .take(32)
        .collect::<Vec<u8>>()
}

pub fn generate_keypair() -> (PublicKey, SecretKey) {
    let (p, s) = box_::gen_keypair();

    (p.into(), s.into())
}

pub fn read_base64_file(filename: &str) -> Vec<u8> {
    let mut data: Vec<u8> = vec![];
    for line in BufReader::new(File::open(filename).unwrap()).lines() {
        data.append(&mut base64::decode(&line.unwrap()).unwrap());
    }

    data
}

fn ct_compare(a: &[u8], b: &[u8]) -> bool {
    debug_assert!(a.len() == b.len());

    a.iter().zip(b).fold(0, |acc, (a, b)| acc | (a ^ b)) == 0
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
