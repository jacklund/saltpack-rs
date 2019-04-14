use crate::cryptotypes::SigningNonce;
use crate::error::Error;
use crate::header::{Header, Mode, Version, FORMAT_NAME, VERSION};
use crate::util::{generate_header_packet, generate_random_signing_nonce};

use base64;
use byteorder::{BigEndian, WriteBytesExt};
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::hash;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::PublicKey as PublicSigningKey;
use sodiumoxide::crypto::sign::SecretKey as SigningKey;
use std::fmt;
use std::io::Read;

const ATTACHED_PREFIX: &[u8] = b"saltpack attached signature\0";
const DETACHED_PREFIX: &[u8] = b"saltpack detached signature\0";

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct SigningHeader {
    format_name: String,
    version: Version,
    pub mode: Mode,
    sender_public_key: PublicSigningKey,
    nonce: SigningNonce,
}

impl SigningHeader {
    pub fn new(detached: bool, public_signing_key: &PublicSigningKey) -> SigningHeader {
        SigningHeader {
            format_name: FORMAT_NAME.to_string(),
            version: VERSION,
            mode: if detached {
                Mode::DetachedSigning
            } else {
                Mode::AttachedSigning
            },
            sender_public_key: *public_signing_key,
            nonce: generate_random_signing_nonce(),
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct AttachedPayloadPacket {
    final_flag: bool,
    signature: sign::Signature,
    #[serde(with = "serde_bytes")] // Needed to be able to decode a bin8 as a byte vector
    payload_chunk: Vec<u8>,
}

impl fmt::Display for SigningHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Header:")?;
        writeln!(f, "  format: {}", self.format_name)?;
        writeln!(f, "  version: {}", self.version)?;
        if self.mode == Mode::AttachedSigning {
            writeln!(f, "  mode: attached signing")?;
        } else {
            writeln!(f, "  mode: detached signing")?;
        }
        writeln!(
            f,
            "  sender_public key: {}",
            base64::encode(&self.sender_public_key)
        )?;
        writeln!(f, "  nonce: {}", base64::encode(&self.nonce))?;

        Ok(())
    }
}

#[derive(Debug)]
pub enum VerifiedResult {
    AttachedSigning(PublicSigningKey, Vec<u8>),
    DetachedSigning(PublicSigningKey),
}

pub fn sign_attached(
    message: &[u8],
    public_signing_key: &PublicSigningKey,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, Error> {
    let header = SigningHeader::new(false, public_signing_key);
    let (header_hash, header_packet) = generate_header_packet(&header);
    let payload_packets = generate_attached_payload_packets(message, signing_key, &header_hash);

    let mut data: Vec<u8> = vec![];
    data.extend(header_packet);
    for payload_packet in payload_packets {
        payload_packet.serialize(&mut Serializer::new(&mut data))?;
    }

    Ok(data)
}

fn generate_attached_payload_packets(
    message: &[u8],
    signing_key: &SigningKey,
    header_hash: &hash::Digest,
) -> Vec<AttachedPayloadPacket> {
    // Output
    let mut packets: Vec<AttachedPayloadPacket> = vec![];

    // 1 MB max chunk size
    let chunk_size: usize = 1024 * 1024;
    let num_chunks: usize = (message.len() as f32 / chunk_size as f32).ceil() as usize;
    for (index, chunk) in message.chunks(chunk_size).enumerate() {
        // Flag if this is the final chunk
        let final_flag: bool = index == num_chunks - 1;

        let signature =
            generate_signature_attached(signing_key, &chunk, header_hash, index, final_flag);

        // Create the packet
        packets.push(AttachedPayloadPacket {
            final_flag,
            signature,
            payload_chunk: chunk.to_vec(),
        });
    }

    packets
}

pub fn sign_detached(
    message: &[u8],
    public_signing_key: &PublicSigningKey,
    signing_key: &SigningKey,
) -> Vec<u8> {
    let header = SigningHeader::new(true, public_signing_key);
    let (header_hash, header_packet) = generate_header_packet(&header);
    let signature = generate_signature_detached(signing_key, message, &header_hash);
    let mut data: Vec<u8> = vec![];
    data.extend(header_packet);
    signature
        .serialize(&mut Serializer::new(&mut data))
        .unwrap();

    data
}

pub fn verify_attached(reader: &mut Read) -> Result<VerifiedResult, Error> {
    // Decode header
    let (header_hash, header) = Header::decode(reader)?;
    let signing_header = match header {
        Header::Signing(signing_header) => Ok(signing_header),
        _ => Err(Error::ValidationError(format!(
            "Expected signing header, got {}",
            header
        ))),
    }?;

    // Verify each payload packet
    let mut de = Deserializer::new(reader);
    let mut packet_index: usize = 0;
    let mut verified = true;
    let mut message: Vec<u8> = vec![];
    loop {
        let packet: AttachedPayloadPacket = Deserialize::deserialize(&mut de)?;
        let packet_verified = verify_signature_attached(
            &signing_header.sender_public_key,
            &packet.payload_chunk,
            packet.signature.as_ref(),
            &header_hash,
            packet_index,
            packet.final_flag,
        );
        verified = verified && packet_verified;
        message.extend(packet.payload_chunk);
        if packet.final_flag {
            if verified {
                return Ok(VerifiedResult::AttachedSigning(
                    signing_header.sender_public_key,
                    message,
                ));
            } else {
                return Err(Error::SignatureNotVerified);
            }
        }
        packet_index += 1;
    }
}

pub fn verify_detached(reader: &mut Read, message: &[u8]) -> Result<VerifiedResult, Error> {
    // Decode header
    let (header_hash, header) = Header::decode(reader)?;
    let signing_header = match header {
        Header::Signing(signing_header) => Ok(signing_header),
        _ => Err(Error::ValidationError(format!(
            "Expected signing header, got {}",
            header
        ))),
    }?;

    let mut de = Deserializer::new(reader);
    let signature: sign::Signature = Deserialize::deserialize(&mut de)?;
    if verify_signature_detached(
        &signing_header.sender_public_key,
        message,
        &signature,
        &header_hash,
    ) {
        Ok(VerifiedResult::DetachedSigning(
            signing_header.sender_public_key,
        ))
    } else {
        Err(Error::SignatureNotVerified)
    }
}

fn generate_signature_data_attached(
    payload_chunk: &[u8],
    header_hash: &hash::Digest,
    packet_index: usize,
    final_flag: bool,
) -> Vec<u8> {
    let mut hash_data: Vec<u8> = vec![];
    hash_data.extend_from_slice(header_hash.as_ref());
    hash_data
        .write_u64::<BigEndian>(packet_index as u64)
        .unwrap();
    hash_data.push(final_flag as u8);
    hash_data.extend(payload_chunk);

    let mut signature_data: Vec<u8> = ATTACHED_PREFIX.to_vec();
    signature_data.extend(hash::sha512::hash(&hash_data).as_ref());

    signature_data
}

fn generate_signature_attached(
    key: &SigningKey,
    payload_chunk: &[u8],
    header_hash: &hash::Digest,
    packet_index: usize,
    final_flag: bool,
) -> sign::Signature {
    let signature_data: Vec<u8> =
        generate_signature_data_attached(payload_chunk, header_hash, packet_index, final_flag);

    sign::sign_detached(&signature_data, &key)
}

fn generate_signature_data_detached(message: &[u8], header_hash: &hash::Digest) -> Vec<u8> {
    let mut hash_data: Vec<u8> = vec![];
    hash_data.extend_from_slice(header_hash.as_ref());
    hash_data.extend(message);

    let mut signature_data: Vec<u8> = DETACHED_PREFIX.to_vec();
    signature_data.extend(hash::sha512::hash(&hash_data).as_ref());

    signature_data
}

fn generate_signature_detached(
    key: &SigningKey,
    message: &[u8],
    header_hash: &hash::Digest,
) -> sign::Signature {
    let signature_data: Vec<u8> = generate_signature_data_detached(message, header_hash);

    sign::sign_detached(&signature_data, &key)
}

fn verify_signature_attached(
    key: &PublicSigningKey,
    payload_chunk: &[u8],
    signature: &[u8],
    header_hash: &hash::Digest,
    packet_index: usize,
    final_flag: bool,
) -> bool {
    let signature_data: Vec<u8> =
        generate_signature_data_attached(payload_chunk, header_hash, packet_index, final_flag);

    sign::verify_detached(
        &sign::Signature::from_slice(signature).unwrap(),
        &signature_data,
        &key,
    )
}

fn verify_signature_detached(
    key: &PublicSigningKey,
    message: &[u8],
    signature: &sign::Signature,
    header_hash: &hash::Digest,
) -> bool {
    let signature_data: Vec<u8> = generate_signature_data_detached(message, header_hash);

    sign::verify_detached(signature, &signature_data, &key)
}

#[cfg(test)]
mod tests {
    use crate::signing::{
        sign_attached, sign_detached, verify_attached, verify_detached, VerifiedResult,
    };
    use crate::util::{generate_random_data, read_base64_file};
    use base64;
    use sodiumoxide::crypto::sign::gen_keypair;

    #[test]
    fn test_verify_detached_interop() {
        let mut data = read_base64_file("fixtures/sign_detached_short.txt");
        let message = b"Hello, World!";
        verify_detached(&mut &data[..], &message[..]).unwrap();
    }

    #[test]
    fn test_sign_verify_detached() {
        let message = generate_random_data(1024 * 1024 * 3);
        let (public_key, secret_key) = gen_keypair();
        let data = sign_detached(&message, &public_key, &secret_key);
        verify_detached(&mut &data[..], &message[..]).unwrap();
    }

    #[test]
    fn test_verify_attached_interop() {
        let mut data = read_base64_file("fixtures/sign_attached_short.txt");
        let result = verify_attached(&mut &data[..]).unwrap();
        match result {
            VerifiedResult::AttachedSigning(key, message) => {
                assert_eq!(b"Hello, World!".to_vec(), message)
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_sign_verify_attached() {
        let message = generate_random_data(1024 * 1024 * 3);
        // let message = b"Hello, World!".to_vec();
        let (public_key, secret_key) = gen_keypair();
        let data = sign_attached(&message, &public_key, &secret_key).unwrap();
        let result = verify_attached(&mut &data[..]).unwrap();
        match result {
            VerifiedResult::AttachedSigning(key, returned_message) => {
                assert_eq!(message, returned_message)
            }
            _ => assert!(false),
        }
    }
}
