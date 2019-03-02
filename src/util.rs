use base64;
use crate::cryptotypes::{FromSlice, PublicKey, SecretKey, SymmetricKey};
use sodiumoxide::crypto::box_;
use rand;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::iter;

pub fn generate_random_key<T: FromSlice<T>>() -> T
{
    T::from_slice(&iter::repeat_with(rand::random::<u8>)
        .take(32)
        .collect::<Vec<u8>>()[..]).unwrap()
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
