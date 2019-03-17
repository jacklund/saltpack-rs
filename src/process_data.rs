use crate::error::Error;
use crate::header::Header;
use crate::keyring::KeyRing;

use sodiumoxide::crypto::secretbox::Key as SymmetricKey;
use std::io::Read;

pub type KeyResolver = fn(&Vec<Vec<u8>>) -> Result<Vec<Option<SymmetricKey>>, Error>;

pub fn process_data(
    reader: &mut Read,
    keyring: &KeyRing,
    key_resolver: KeyResolver,
) -> Result<Vec<u8>, Error> {
    let (header_hash, header) = Header::decode(reader)?;
    let handler = header.get_handler(header_hash, keyring, key_resolver)?;
    handler.process_payload(reader)
}
