use crate::base62;
use crate::header::Mode;
use regex::Regex;
use std::io::{BufReader, BufWriter, Bytes, ErrorKind, Read, Write};
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
    static ref WHITESPACE_LIST: [u8; 5] = [b'>', b'\n', b'\r', b'\t', b' '];
}

const BLOCK_LENGTH: usize = 42;

pub struct ArmorReader<'a> {
    bytes: Bytes<BufReader<&'a mut (dyn Read + 'a)>>,
    result_buffer: Vec<u8>,
    header_read: bool,
    finished_reading: bool,
}

impl<'a> ArmorReader<'a> {
    pub fn new(reader: &'a mut Read) -> Self {
        ArmorReader {
            bytes: BufReader::new(reader).bytes(),
            result_buffer: vec![],
            header_read: false,
            finished_reading: false,
        }
    }

    fn copy_result_to(&mut self, buf: &mut [u8]) -> usize {
        let copy_length: usize = std::cmp::min(buf.len(), self.result_buffer.len());
        if self.result_buffer.len() > copy_length {
            let tmp = self.result_buffer.split_off(copy_length);
            buf[..copy_length].clone_from_slice(&self.result_buffer[..copy_length]);
            self.result_buffer = tmp;
        } else {
            buf[..copy_length].clone_from_slice(&self.result_buffer[..copy_length]);
            self.result_buffer.clear();
        }

        copy_length
    }
}

pub struct ArmorWriter<'a> {
    writer: BufWriter<&'a mut (dyn Write + 'a)>,
    write_buffer: Vec<u8>,
    mode: Mode,
    header_written: bool,
    closed: bool,
}

impl<'a> ArmorWriter<'a> {
    pub fn new(writer: &'a mut Write, mode: Mode) -> Self {
        ArmorWriter {
            writer: BufWriter::new(writer),
            write_buffer: vec![],
            mode,
            header_written: false,
            closed: false,
        }
    }

    fn flush_write_buffer(&mut self, close: bool) -> std::io::Result<()> {
        let mut tmp: Option<Vec<u8>> = None;
        for chunk in self.write_buffer.chunks(15) {
            if chunk.len() == 15 || close {
                self.writer
                    .write_fmt(format_args!(" {}", str::from_utf8(chunk).unwrap()))?;
            } else {
                tmp = Some(chunk.to_vec());
            }
        }

        self.write_buffer = tmp.unwrap_or(vec![]);

        Ok(())
    }

    pub fn close(&mut self) -> std::io::Result<()> {
        let mut ret = Ok(());
        if !self.closed {
            self.flush_write_buffer(true)?;
            self.writer.write_fmt(format_args!(". "))?;
            write_footer(&mut self.writer, &self.mode)?;
            ret = self.flush();
            self.closed = true;
        }
        ret
    }
}

impl<'a> Read for ArmorReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.finished_reading {
            return Ok(0);
        }

        if !self.header_read {
            read_header(&mut self.bytes)?;
            self.header_read = true;
        }

        while self.result_buffer.len() < buf.len() && !self.finished_reading {
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

impl<'a> Write for ArmorWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.header_written {
            write_header(&mut self.writer, &self.mode)?;
            self.header_written = true;
        }

        self.write_buffer
            .extend(buf.chunks(BLOCK_LENGTH).map(|c| base62::encode(&c)).fold(
                vec![],
                |mut acc, s| {
                    acc.extend_from_slice(s.as_bytes());
                    acc
                },
            ));

        self.flush_write_buffer(false)?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_write_buffer(false)?;
        self.writer.flush()
    }
}

impl<'a> Drop for ArmorWriter<'a> {
    fn drop(&mut self) {
        if !self.closed {
            self.close().unwrap();
        }
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

fn write_header<'a>(
    writer: &mut BufWriter<&'a mut (dyn Write + 'a)>,
    mode: &Mode,
) -> std::io::Result<()> {
    writer.write_fmt(format_args!(
        "BEGIN SALTPACK {} MESSAGE.",
        match mode {
            Mode::Encryption => "ENCRYPTED",
            Mode::AttachedSigning | Mode::DetachedSigning => "SIGNED",
            Mode::Signcryption => "SIGNCRYPTED",
        },
    ))
}

fn decode(buffer: &[u8]) -> std::io::Result<String> {
    Ok(str::from_utf8(buffer)
        .map_err(|_| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                "Armor payload is not utf-8".to_string(),
            )
        })?
        .to_string())
}

fn read_block<'a>(
    bytes: &mut Bytes<BufReader<&'a mut (dyn Read + 'a)>>,
) -> std::io::Result<Vec<u8>> {
    bytes
        .filter(|result| match result {
            Ok(byte) => !WHITESPACE_LIST.contains(byte),
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

fn write_footer<'a>(
    writer: &mut BufWriter<&'a mut (dyn Write + 'a)>,
    mode: &Mode,
) -> std::io::Result<()> {
    writer.write_fmt(format_args!(
        "END SALTPACK {} MESSAGE.",
        match mode {
            Mode::Encryption => "ENCRYPTED",
            Mode::AttachedSigning | Mode::DetachedSigning => "SIGNED",
            Mode::Signcryption => "SIGNCRYPTED",
        },
    ))
}

#[cfg(test)]
mod tests {
    use crate::armor::{ArmorReader, ArmorWriter};
    use crate::header::Mode;
    use crate::util::generate_random_data;
    use std::fs::File;
    use std::io::{BufReader, Read, Write};
    use std::str;

    #[test]
    fn test_read_armor() {
        let mut file = File::open("fixtures/armored.txt").unwrap();
        let armor: ArmorReader = ArmorReader::new(&mut file);
        let mut reader = BufReader::new(armor);
        let mut buffer: Vec<u8> = vec![];
        reader.read_to_end(&mut buffer).unwrap();
    }

    #[test]
    fn test_write_armor() {
        // let data = generate_random_data(1024);
        let data = b"Hello, World!";
        let mut output: Vec<u8> = vec![];
        {
            let mut armor: ArmorWriter = ArmorWriter::new(&mut output, Mode::Encryption);
            armor.write(&data[..]).unwrap();
            armor.close().unwrap();
        }
        let mut slice: &[u8] = &mut output;
        let armor: ArmorReader = ArmorReader::new(&mut slice);
        let mut reader = BufReader::new(armor);
        let mut buffer: Vec<u8> = vec![];
        reader.read_to_end(&mut buffer).unwrap();
        // assert_eq!(data.len(), buffer.len());
        assert_eq!(data.to_vec(), buffer);
    }
}
