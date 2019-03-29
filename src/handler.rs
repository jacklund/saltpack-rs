use crate::error::Error;
use crate::process_data::DecryptedResult;

use std::io::Read;

pub trait Handler {
    fn process_payload(&self, reader: &mut Read) -> Result<DecryptedResult, Error>;
}
