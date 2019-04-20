use crate::base62;
use regex::Regex;
use std::io::{BufReader, Bytes, ErrorKind, Read};
use std::str;

lazy_static! {
    static ref HEADER_REGEX: Regex = Regex::new(concat!(
        r"^[>\n\r\t ]*BEGIN[>\n\r\t ]+([a-zA-Z0-9]+[>\n\r\t ]+)",
        r"?SALTPACK[>\n\r\t ]+(ENCRYPTED[>\n\r\t ]+MESSAGE|SIGNED",
        r"[>\n\r\t ]+MESSAGE|DETACHED[>\n\r\t ]+SIGNATURE)[>\n\r\t ]*$"
    ))
    .unwrap();
    static ref FOOTER_REGEX: Regex = Regex::new(concat!(
        r"^[>\n\r\t ]*END[>\n\r\t ]+([a-zA-Z0-9]+[>\n\r\t ]+)",
        r"?SALTPACK[>\n\r\t ]+(ENCRYPTED[>\n\r\t ]+MESSAGE|SIGNED",
        r"[>\n\r\t ]+MESSAGE|DETACHED[>\n\r\t ]+SIGNATURE)[>\n\r\t ]*$"
    ))
    .unwrap();
    static ref WHITESPACE_REGEX: Regex = Regex::new(r"[>\n\r\t ]").unwrap();
}

const BLOCK_LENGTH: usize = 42;

pub struct Armor<'a> {
    bytes: Bytes<BufReader<&'a mut (dyn Read + 'a)>>,
    result_buffer: Vec<u8>,
    header_read: bool,
    finished_reading: bool,
}

impl<'a> Armor<'a> {
    pub fn new(reader: &'a mut Read) -> Self {
        Armor {
            bytes: BufReader::new(reader).bytes(),
            result_buffer: vec![],
            header_read: false,
            finished_reading: false,
        }
    }

    fn copy_result_to(&mut self, buf: &mut [u8]) -> usize {
        let copy_length: usize = std::cmp::min(buf.len(), self.result_buffer.len());
        self.result_buffer
            .drain(..copy_length)
            .enumerate()
            .for_each(|(i, b)| buf[i] = b);

        copy_length
    }
}

fn decode(buffer: &[u8]) -> std::io::Result<String> {
    Ok(remove_whitespace(&str::from_utf8(buffer).map_err(
        |_| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                "Armor payload is not utf-8".to_string(),
            )
        },
    )?))
}

impl<'a> Read for Armor<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.finished_reading {
            return Ok(0);
        }

        if !self.header_read {
            read_header(&mut self.bytes)?;
            self.header_read = true;
        }

        if self.result_buffer.len() < buf.len() {
            let read_buffer = read_block(&mut self.bytes)?;
            let payload = decode(&read_buffer[..])?;
            self.result_buffer
                .extend_from_slice(&base62::decode(&payload)?);
            if read_buffer.len() < BLOCK_LENGTH {
                read_footer(&mut self.bytes)?;
                self.finished_reading = true;
            }
        }

        Ok(self.copy_result_to(buf))
    }
}

fn read_header<'a>(bytes: &mut Bytes<BufReader<&'a mut (dyn Read + 'a)>>) -> std::io::Result<()> {
    let header_bytes = bytes
        .take_while(|result| match result {
            Ok(byte) => *byte != b'.',
            Err(_) => false,
        })
        .collect::<std::io::Result<Vec<u8>>>()?;
    let header = str::from_utf8(&header_bytes).map_err(|_| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            "Armor header is not utf-8".to_string(),
        )
    })?;
    if HEADER_REGEX.is_match(header) {
        Ok(())
    } else {
        Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "Armor header incorrect".to_string(),
        ))
    }
}

fn read_block<'a>(
    bytes: &mut Bytes<BufReader<&'a mut (dyn Read + 'a)>>,
) -> std::io::Result<Vec<u8>> {
    bytes
        .filter(|result| match result {
            Ok(byte) => *byte != b' ',
            Err(_) => true,
        })
        .take_while(|result| match result {
            Ok(byte) => *byte != b'.',
            Err(_) => false,
        })
        .take(BLOCK_LENGTH)
        .collect::<std::io::Result<Vec<u8>>>()
}

fn read_footer<'a>(bytes: &mut Bytes<BufReader<&'a mut (dyn Read + 'a)>>) -> std::io::Result<()> {
    let footer_bytes = bytes
        .take_while(|result| match result {
            Ok(byte) => *byte != b'.',
            Err(_) => false,
        })
        .collect::<std::io::Result<Vec<u8>>>()?;
    let footer = str::from_utf8(&footer_bytes).map_err(|_| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            "Armor footer is not utf-8".to_string(),
        )
    })?;
    if !FOOTER_REGEX.is_match(footer) {
        Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "Armor footer incorrect".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn remove_whitespace(string: &str) -> String {
    WHITESPACE_REGEX.replace_all(string, "").to_string()
}

#[cfg(test)]
mod tests {
    use crate::armor::Armor;
    use std::fs::File;
    use std::io::{BufReader, Read};

    #[test]
    fn test_read_armor() {
        let mut file = File::open("fixtures/armored.txt").unwrap();
        let armor: Armor = Armor::new(&mut file);
        let mut reader = BufReader::new(armor);
        let mut buffer: Vec<u8> = vec![];
        reader.read_to_end(&mut buffer).unwrap();
    }
}
