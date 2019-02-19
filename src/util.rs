use base64;
use rand;
use std::iter;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn generate_random_key() -> Vec<u8> {
    iter::repeat_with(rand::random::<u8>)
        .take(32)
        .collect::<Vec<u8>>()
}

pub fn read_base64_file(filename: &str) -> Vec<u8> {
    let mut data: Vec<u8> = vec![];
    for line in BufReader::new(File::open(filename).unwrap()).lines() {
        data.append(&mut base64::decode(&line.unwrap()).unwrap());
    }

    data
}
