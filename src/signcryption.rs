use serde_bytes;

use crate::error::Error;
use crate::handler::Handler;
use crate::header::Mode;
use crate::cryptotypes::{MacKey, PublicKey, SymmetricKey};
use crate::keyring::KeyRing;
use base64;
use sodiumoxide::crypto::{box_, hash};
use std::fmt;
use std::io::Read;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SigncryptionRecipientPair {
    #[serde(with = "serde_bytes")]
    recipient_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    payload_key_box: Vec<u8>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct SigncryptionHeader {
    format_name: String,
    version: [u32; 2],
    mode: Mode,
    public_key: box_::PublicKey,
    #[serde(with = "serde_bytes")]
    sender_secretbox: Vec<u8>,
    recipients_list: Vec<SigncryptionRecipientPair>,
}

impl SigncryptionHeader {
    pub fn get_handler(
        &self,
        header_hash: hash::Digest,
        keyring: &KeyRing,
    ) -> Result<Box<Handler>, Error> {
        unimplemented!()
    }
}

impl fmt::Display for SigncryptionHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Header:")?;
        writeln!(f, "  format: {}", self.format_name)?;
        writeln!(f, "  version: {}.{}", self.version[0], self.version[1])?;
        writeln!(f, "  mode: signcryption")?;
        writeln!(f, "  public key: {}", base64::encode(&self.public_key))?;
        writeln!(
            f,
            "  sender secretbox: {}",
            base64::encode(&self.sender_secretbox)
        )?;
        let mut index = 0;
        for recipient in self.recipients_list.clone() {
            writeln!(f, "  recipient {}:", index)?;
            writeln!(
                f,
                "    recipient id: {}",
                base64::encode(&recipient.recipient_id)
            )?;
            writeln!(
                f,
                "    payload key box: {}",
                base64::encode(&recipient.payload_key_box)
            )?;
            index += 1;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct SigncryptionHandler {
    pub payload_key: SymmetricKey,
    pub sender_public_key: PublicKey,
    pub mac_key: MacKey,
    pub header_hash: hash::Digest,
}

impl SigncryptionHandler {
    pub fn new(
        payload_key: SymmetricKey,
        sender_public_key: PublicKey,
        mac_key: MacKey,
        header_hash: hash::Digest,
    ) -> SigncryptionHandler {
        SigncryptionHandler {
            payload_key,
            sender_public_key,
            mac_key,
            header_hash,
        }
    }
}

impl Handler for SigncryptionHandler {
    fn process_payload(&self, reader: &mut Read) -> Result<Vec<u8>, Error> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use crate::header::Header;
    use crate::util::read_base64_file;
    use rmp::decode;
    use rmp_serde::Deserializer;
    use serde::Deserialize;
    use std::io::Cursor;

    #[test]
    fn test_read_signcryption_header() {
        let data: Vec<u8> = read_base64_file("fixtures/signcryption.txt");
        let bin_header_len: usize = decode::read_bin_len(&mut data.as_slice()).unwrap() as usize;
        let bin_header: Vec<u8> = data[3..(bin_header_len + 3)].to_vec();
        let cur = Cursor::new(&bin_header[..]);
        let mut de = Deserializer::new(cur);
        let header: Header = Deserialize::deserialize(&mut de).unwrap();
        if let Header::Signcryption(signcryption_header) = header {
            assert_eq!(15, signcryption_header.recipients_list.len());
        } else {
            assert!(false);
        }
    }
}
