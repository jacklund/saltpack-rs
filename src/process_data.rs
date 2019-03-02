use crate::error::Error;
use crate::handler::Handler;
use crate::header::Header;
use crate::keyring::KeyRing;

use std::io::Read;

pub fn process_data(reader: &mut Read, keyring: &KeyRing) -> Result<Vec<u8>, Error> {
    let (header_hash, header) = Header::decode(reader)?;
    let handler = header.get_handler(header_hash, keyring)?;
    handler.process_payload(reader)
}
