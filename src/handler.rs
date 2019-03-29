use crate::decrypt::DecryptedResult;
use crate::error::Error;

use std::io::Read;

pub trait Handler {
    fn process_payload(&self, reader: &mut Read) -> Result<DecryptedResult, Error>;
}
