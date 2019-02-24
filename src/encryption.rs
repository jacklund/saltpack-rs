use base64;
use byteorder::{BigEndian, WriteBytesExt};
use rmp::encode;
use rmp_serde::Serializer;
use serde::Serialize;
use serde_bytes;
use sodiumoxide::crypto::{auth, box_, hash, secretbox};
use std::fmt;
use std::iter;

use crate::header::{
    create_sender_secretbox, encrypt_payload_key_for_recipient, Mode, FORMAT_NAME, VERSION,
};
use crate::keys::{PublicKey, SecretKey};
use crate::util::generate_random_key;

pub fn encrypt(sender_key: &SecretKey, recipients: &[PublicKey], message: &[u8]) -> Vec<u8> {
    // Generate payload key
    let payload_key: Vec<u8> = generate_random_key();

    // Generate ephemeral keypair
    let (ephemeral_public_key, ephemeral_secret_key) = box_::gen_keypair();

    // Generate encryption header
    let header: EncryptionHeader = EncryptionHeader::new(
        sender_key,
        recipients,
        &payload_key,
        &ephemeral_public_key,
        &ephemeral_secret_key,
    );

    // Generate header packet and header hash
    let (header_hash, header_packet) = header.generate_header_packet();

    // Generate per-recipient mac keys
    let recipient_mac_keys: Vec<Vec<u8>> =
        generate_recipient_mac_keys(recipients, &header_hash, &sender_key, &ephemeral_secret_key);

    // Generate the payload packets
    let payload_packets: Vec<PayloadPacket> =
        generate_payload_packets(message, &payload_key, &header_hash, &recipient_mac_keys);

    // Put it all together
    let mut data: Vec<u8> = vec![];
    data.extend(header_packet);
    for payload_packet in payload_packets {
        payload_packet
            .serialize(&mut Serializer::new(&mut data))
            .unwrap();
    }

    data
}

pub fn generate_recipient_mac_keys(
    recipients: &[PublicKey],
    header_hash: &hash::Digest,
    sender_key: &SecretKey,
    ephemeral_secret_key: &box_::SecretKey,
) -> Vec<Vec<u8>> {
    let mut recipient_mac_keys: Vec<Vec<u8>> = vec![];
    for (recipient_index, recipient) in recipients.iter().enumerate() {
        let mut recipient_nonce: Vec<u8> =
            generate_recipient_nonce(header_hash, recipient_index as u64);

        // Encrypt zero bytes with recipients public key and modified nonce
        recipient_nonce[15] &= 0xfe;
        let zero_bytes: Vec<u8> = iter::repeat(0u8).take(32).collect();
        let encrypted1 = box_::seal(
            &zero_bytes,
            &box_::Nonce::from_slice(&recipient_nonce).unwrap(),
            &box_::PublicKey::from_slice(recipient).unwrap(),
            &box_::SecretKey::from_slice(sender_key).unwrap(),
        );

        // Encrypt zero bytes with recipients public key and modified nonce
        recipient_nonce[15] |= 0x01;
        let encrypted2 = box_::seal(
            &zero_bytes,
            &box_::Nonce::from_slice(&recipient_nonce).unwrap(),
            &box_::PublicKey::from_slice(recipient).unwrap(),
            &ephemeral_secret_key,
        );

        // Combine parts of the two encrypted tokens and hash that
        let mut encrypted_buf: Vec<u8> = vec![];
        encrypted_buf.copy_from_slice(&encrypted1[32..]);
        encrypted_buf.copy_from_slice(&encrypted2[32..]);
        let mac_digest: hash::Digest = hash::sha512::hash(&encrypted_buf);
        recipient_mac_keys.push(mac_digest[..32].to_vec());
    }

    recipient_mac_keys
}

// Generate the recipient nonce from part of the header hash and the recipient index
fn generate_recipient_nonce(header_hash: &hash::Digest, index: u64) -> Vec<u8> {
    let mut recipient_nonce: Vec<u8> = vec![];
    recipient_nonce.copy_from_slice(&header_hash[..16]);
    recipient_nonce.write_u64::<BigEndian>(index).unwrap();

    recipient_nonce
}

fn generate_payload_packets(
    message: &[u8],
    payload_key: &[u8],
    header_hash: &hash::Digest,
    mac_keys: &[Vec<u8>],
) -> Vec<PayloadPacket> {
    // Output
    let mut packets: Vec<PayloadPacket> = vec![];

    // 1 MB max chunk size
    let chunk_size: usize = 1024 * 1024;
    for (index, chunk) in message.chunks(chunk_size).enumerate() {
        // Encrypt the chunk with the payload key and generated nonce
        let payload_secretbox_nonce: Vec<u8> = generate_payload_secretbox_nonce(index as u64);
        let payload_secretbox: Vec<u8> = secretbox::seal(
            &chunk,
            &secretbox::Nonce::from_slice(&payload_secretbox_nonce).unwrap(),
            &secretbox::Key::from_slice(&payload_key).unwrap(),
        );

        // Flag if this is the final chunk
        let final_flag: bool = chunk.len() < chunk_size;

        // Authenticators for each recipient
        let authenticators: Vec<Vec<u8>> = generate_authenticators(
            header_hash,
            &payload_secretbox_nonce,
            final_flag,
            &payload_secretbox,
            mac_keys,
        );

        // Create the packet
        packets.push(PayloadPacket {
            final_flag,
            authenticators,
            payload_secretbox,
        });
    }

    packets
}

fn generate_authenticators(
    header_hash: &hash::Digest,
    payload_secretbox_nonce: &[u8],
    final_flag: bool,
    payload_secretbox: &[u8],
    mac_keys: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    // Authenticator data is the header hash || nonce || final flag || secret box
    let mut authenticator_data: Vec<u8> = vec![];
    authenticator_data.copy_from_slice(&header_hash[..]);
    authenticator_data.copy_from_slice(payload_secretbox_nonce);
    authenticator_data.push(final_flag as u8);
    authenticator_data.copy_from_slice(payload_secretbox);
    let mut authenticators: Vec<Vec<u8>> = vec![];
    for key in mac_keys {
        authenticators.push(
            auth::authenticate(
                &hash::sha512::hash(&authenticator_data)[..],
                &auth::Key::from_slice(&key).unwrap(),
            )[..]
                .to_vec(),
        );
    }

    authenticators
}

fn generate_payload_secretbox_nonce(index: u64) -> Vec<u8> {
    let mut nonce: Vec<u8> = vec![];
    nonce.copy_from_slice(b"saltpack_ploadsb");
    nonce.write_u64::<BigEndian>(index as u64).unwrap();

    nonce
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EncryptionRecipientPair {
    public_key: Option<PublicKey>,
    #[serde(with = "serde_bytes")]
    payload_key_box: Vec<u8>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct EncryptionHeader {
    pub format_name: String,
    pub version: [u32; 2],
    pub mode: Mode,
    pub public_key: box_::PublicKey,
    #[serde(with = "serde_bytes")]
    pub sender_secretbox: Vec<u8>,
    pub recipients_list: Vec<EncryptionRecipientPair>,
}

impl EncryptionHeader {
    pub fn new(
        sender: &SecretKey,
        recipients: &[PublicKey],
        payload_key: &[u8],
        ephemeral_public_key: &box_::PublicKey,
        ephemeral_secret_key: &box_::SecretKey,
    ) -> Self {
        // Create sender_secretbox
        let sender_secretbox = create_sender_secretbox(&sender, &payload_key);

        // Encrypt payload key for each recipient and (optionally) add their public key
        let mut recipients_list: Vec<EncryptionRecipientPair> = vec![];
        for (index, recipient) in recipients.iter().enumerate() {
            let payload_key_box = encrypt_payload_key_for_recipient(
                &recipient,
                index as u64,
                &payload_key,
                &ephemeral_secret_key,
            );
            recipients_list.push(EncryptionRecipientPair {
                public_key: Some(*recipient),
                payload_key_box,
            });
        }

        // Return the header
        EncryptionHeader {
            format_name: FORMAT_NAME.to_string(),
            version: VERSION,
            mode: Mode::EncryptionMode,
            public_key: *ephemeral_public_key,
            sender_secretbox,
            recipients_list,
        }
    }

    // Serialize the packet, generate the hash of the serialized packet,
    // then re-encode the serialized packet as a msgpack bin object
    pub fn generate_header_packet(&self) -> (hash::Digest, Vec<u8>) {
        let mut buf: Vec<u8> = vec![];
        self.serialize(&mut Serializer::new(&mut buf)).unwrap();
        let digest: hash::Digest = hash::sha512::hash(&buf);
        let mut packet: Vec<u8> = vec![];
        encode::write_bin(&mut packet, &buf).unwrap();
        (digest, packet)
    }
}

impl fmt::Display for EncryptionHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Header:")?;
        writeln!(f, "  format: {}", self.format_name)?;
        writeln!(f, "  version: {}.{}", self.version[0], self.version[1])?;
        writeln!(f, "  mode: encryption")?;
        writeln!(f, "  public key: {}", base64::encode(&self.public_key))?;
        writeln!(
            f,
            "  sender secretbox: {}",
            base64::encode(&self.sender_secretbox)
        )?;
        for (index, recipient) in self.recipients_list.iter().enumerate() {
            writeln!(f, "  recipient {}:", index)?;
            writeln!(
                f,
                "    public key: {}",
                if recipient.public_key.is_none() {
                    "nil".to_string()
                } else {
                    base64::encode(&recipient.public_key.unwrap())
                }
            )?;
            writeln!(
                f,
                "    payload key box: {}",
                base64::encode(&recipient.payload_key_box)
            )?;
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct PayloadPacket {
    final_flag: bool,
    authenticators: Vec<Vec<u8>>,
    payload_secretbox: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use crate::encryption::{encrypt, EncryptionHeader};
    use crate::header::Header;
    use crate::keys::{from_binary, PublicKey, SecretKey};
    use crate::util::{generate_random_key, read_base64_file};
    use rmp::decode;
    use rmp_serde::{Deserializer, Serializer};
    use serde::{Deserialize, Serialize};
    use sodiumoxide::crypto::box_;
    use std::io::Cursor;

    #[test]
    fn test_encrypt() {
        let sender: SecretKey = from_binary(&generate_random_key()).unwrap();
        let mut recipients: Vec<PublicKey> = vec![];
        for _ in 0..4 {
            recipients.push(from_binary(&generate_random_key()).unwrap());
        }

        let ciphertext = encrypt(&sender, &recipients, b"Hello, World!");
        println!("{:X?}", ciphertext);
        assert!(false);
    }

    #[test]
    fn test_serialize_deserialize_encryption_header() {
        // Generate payload key
        let payload_key: Vec<u8> = generate_random_key();

        // Generate ephemeral keypair
        let (ephemeral_public_key, ephemeral_secret_key) = box_::gen_keypair();

        let sender: SecretKey = from_binary(&generate_random_key()).unwrap();
        let mut recipients: Vec<PublicKey> = vec![];
        for _ in 0..4 {
            recipients.push(from_binary(&generate_random_key()).unwrap());
        }

        let header: EncryptionHeader = EncryptionHeader::new(
            &sender,
            &recipients,
            &payload_key,
            &ephemeral_public_key,
            &ephemeral_secret_key,
        );

        let mut buf: Vec<u8> = vec![];
        header.serialize(&mut Serializer::new(&mut buf)).unwrap();
        let mut de = Deserializer::new(&buf[..]);
        let foo: EncryptionHeader = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(header, foo);
    }

    #[test]
    fn test_read_encryption_header() {
        let data: Vec<u8> = read_base64_file("fixtures/encryption.txt");
        let bin_header_len: usize = decode::read_bin_len(&mut data.as_slice()).unwrap() as usize;
        let bin_header: Vec<u8> = data[3..(bin_header_len + 3)].to_vec();
        let cur = Cursor::new(&bin_header[..]);
        let mut de = Deserializer::new(cur);
        let header: Header = Deserialize::deserialize(&mut de).unwrap();
        if let Header::Encryption(encryption_header) = header {
            assert_eq!(14, encryption_header.recipients_list.len());
        } else {
            assert!(false);
        }
    }
}
