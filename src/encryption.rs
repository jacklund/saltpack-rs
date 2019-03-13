use base64;
use byteorder::{BigEndian, WriteBytesExt};
use rmp::encode;
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use serde_bytes;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
use sodiumoxide::crypto::secretbox::Key as SymmetricKey;
use sodiumoxide::crypto::{auth, box_, hash, secretbox};
use std::fmt;
use std::io::Read;

use crate::cryptotypes::{Authenticator, FromSlice, MacKey, Nonce};
use crate::error::Error;
use crate::handler::Handler;
use crate::header::{Mode, Version, FORMAT_NAME, VERSION};
use crate::keyring::KeyRing;
use crate::util::{
    cryptobox_zero_bytes, generate_keypair, generate_random_symmetric_key, generate_recipient_nonce,
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EncryptionRecipientPair {
    public_key: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    payload_key_box: Vec<u8>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct EncryptionHeader {
    pub format_name: String,
    pub version: Version,
    pub mode: Mode,
    pub public_key: PublicKey,
    #[serde(with = "serde_bytes")]
    pub sender_secretbox: Vec<u8>,
    pub recipients_list: Vec<EncryptionRecipientPair>,
}

impl  EncryptionHeader {
    pub fn new(
        sender: &PublicKey,
        recipients: &[PublicKey],
        payload_key: &SymmetricKey,
        ephemeral_public_key: &PublicKey,
        ephemeral_secret_key: &SecretKey,
    ) -> Self {
        // Create sender_secretbox
        let sender_secretbox = create_sender_secretbox(&sender, &payload_key);

        // Encrypt payload key for each recipient and (optionally) add their public key
        let mut recipients_list: Vec<EncryptionRecipientPair> = vec![];
        for (index, recipient) in recipients.iter().enumerate() {
            let payload_key_box = encrypt_payload_key_for_recipient(
                &recipient,
                index as u64,
                payload_key,
                &ephemeral_secret_key,
            );
            recipients_list.push(EncryptionRecipientPair {
                public_key: Some(recipient.0.to_vec().into()),
                payload_key_box,
            });
        }

        // Return the header
        EncryptionHeader {
            format_name: FORMAT_NAME.to_string(),
            version: VERSION,
            mode: Mode::Encryption,
            public_key: ephemeral_public_key.clone(),
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

    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut de = Deserializer::new(buf);
        Ok(Deserialize::deserialize(&mut de)?)
    }

    pub fn get_handler(
        &self,
        header_hash: hash::Digest,
        keyring: &KeyRing,
    ) -> Result<Box<Handler>, Error> {
        // Validate the expected values
        // self.validate()?;

        // Are any of our recipients anonymous?
        // let has_anonymous = self.recipients_list.iter().any(|r| r.public_key.is_none());
        let has_anonymous = false;

        // Get a list of any secret keys of known recipients we
        // have in our keyring
        let mut secret_key_list: Vec<&SecretKey> = self
            .recipients_list
            .iter()
            .filter_map(|r| r.public_key.clone())
            .map(|p| keyring.find_encryption_key(&PublicKey::from_slice(&p).unwrap()))
            .filter(|&s| s.is_some())
            .map(|s| s.unwrap())
            .collect();

        // If we have anonymous recipients, append all the secret
        // keys in case we need to go through them all
        if has_anonymous {
            secret_key_list.extend(keyring.get_all_encryption_keys())
        }

        // Get all the payload key boxes from the recipients list
        let key_boxes: Vec<Vec<u8>> = self
            .recipients_list
            .iter()
            .map(|r| r.clone().payload_key_box)
            .collect();

        // Try to decrypt the payload key
        let opt_payload_key =
            try_decrypt_payload_key(&secret_key_list, &self.public_key, &key_boxes);

        if opt_payload_key.is_none() {
            return Err(Error::DecryptionError(
                "No secret key found to decrypt message".to_string(),
            ));
        }

        let (recipient_index, secret_key, payload_key) = opt_payload_key.unwrap();

        // Decrypt the sender secret box
        let sender_public_key = open_sender_secretbox(&self.sender_secretbox, &payload_key)?;

        // Generate mac key
        let mac_key = generate_recipient_mac_key(
            &header_hash,
            recipient_index,
            &sender_public_key.clone().into(),
            &self.public_key,
            &secret_key.clone().into(),
            &secret_key.clone().into(),
        );

        Ok(Box::new(EncryptionHandler::new(
            recipient_index as usize,
            payload_key,
            sender_public_key,
            mac_key,
            header_hash,
        )))
    }
}

#[derive(Debug)]
pub struct EncryptionHandler {
    pub recipient_index: usize,
    pub payload_key: SymmetricKey,
    pub sender_public_key: PublicKey,
    pub mac_key: MacKey,
    pub header_hash: hash::Digest,
}

impl EncryptionHandler {
    pub fn new(
        recipient_index: usize,
        payload_key: SymmetricKey,
        sender_public_key: PublicKey,
        mac_key: MacKey,
        header_hash: hash::Digest,
    ) -> EncryptionHandler {
        EncryptionHandler {
            recipient_index,
            payload_key,
            sender_public_key,
            mac_key,
            header_hash,
        }
    }

    fn process_packet(
        &self,
        packet: &PayloadPacket,
        packet_index: usize,
    ) -> Result<Vec<u8>, Error> {
        let payload_secretbox_nonce: Nonce =
            generate_payload_secretbox_nonce(self.recipient_index as u64);
        let authenticator: Authenticator = generate_authenticator(
            &generate_authenticator_data(
                &self.header_hash,
                &payload_secretbox_nonce,
                packet.final_flag,
                &packet.payload_secretbox,
            ),
            &self.mac_key,
        );

        if authenticator != packet.authenticators[self.recipient_index] {
            return Err(Error::AuthenticationError(
                "Authenticators did not match for packet".to_string(),
            ));
        }

        let result = secretbox::open(
            &packet.payload_secretbox,
            &payload_secretbox_nonce.into(),
            &self.payload_key.clone().into(),
        );
        if let Err(_) = result {
            return Err(Error::DecryptionError(
                "Error opening packet secretbox".to_string(),
            ));
        }

        Ok(result.unwrap())
    }
}

impl Handler for EncryptionHandler {
    fn process_payload(&self, reader: &mut Read) -> Result<Vec<u8>, Error> {
        let mut ret: Vec<u8> = vec![];
        let mut de = Deserializer::new(reader);
        let mut packet_index: usize = 0;
        loop {
            let packet: PayloadPacket = Deserialize::deserialize(&mut de)?;
            ret.extend(self.process_packet(&packet, packet_index)?);
            if packet.final_flag {
                break;
            }
            packet_index += 1;
        }

        Ok(ret)
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct PayloadPacket {
    final_flag: bool,
    authenticators: Vec<Authenticator>,
    payload_secretbox: Vec<u8>,
}

fn try_decrypt_payload_key<'a>(
    secret_key_list: &[&'a SecretKey],
    ephemeral_public_key: &PublicKey,
    key_boxes: &[Vec<u8>],
) -> Option<(u64, &'a SecretKey, SymmetricKey)> {
    for secret_key in secret_key_list {
        let precomputed_key =
            box_::precompute(&ephemeral_public_key, &(*secret_key).clone().into());
        for (index, key_box) in key_boxes.iter().enumerate() {
            let nonce = generate_recipient_nonce(index as u64);
            if let Ok(payload_key) =
                box_::open_precomputed(&key_box, &nonce.into(), &precomputed_key)
            {
                return Some((
                    index as u64,
                    secret_key,
                    SymmetricKey::from_slice(&payload_key).unwrap(),
                ));
            }
        }
    }

    None
}

pub fn encrypt(
    sender_secret_key: &SecretKey,
    sender_public_key: &PublicKey,
    recipients: &[PublicKey],
    message: &[u8],
) -> Vec<u8> {
    // Generate payload key
    let payload_key: SymmetricKey = generate_random_symmetric_key();

    // Generate ephemeral keypair
    let (ephemeral_public_key, ephemeral_secret_key) = generate_keypair();

    // Generate encryption header
    let header: EncryptionHeader = EncryptionHeader::new(
        sender_public_key,
        recipients,
        &payload_key,
        &ephemeral_public_key,
        &ephemeral_secret_key,
    );

    // Generate header packet and header hash
    let (header_hash, header_packet) = header.generate_header_packet();

    // Generate per-recipient mac keys
    let recipient_mac_keys: Vec<MacKey> = generate_encryption_mac_keys(
        recipients,
        &header_hash,
        &sender_secret_key,
        &ephemeral_secret_key,
    );

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

fn generate_recipient_mac_key(
    header_hash: &hash::Digest,
    recipient_index: u64,
    public_key1: &PublicKey,
    public_key2: &PublicKey,
    secret_key1: &SecretKey,
    secret_key2: &SecretKey,
) -> MacKey {
    let mut recipient_nonce: Nonce =
        generate_recipient_mac_nonce(header_hash, recipient_index as u64);

    // Encrypt zero bytes with first public key, first private key, and modified nonce
    recipient_nonce[15] &= 0xfe;
    let encrypted1 =
        cryptobox_zero_bytes(&recipient_nonce.clone().into(), public_key1, secret_key1);

    // Encrypt zero bytes with second public key, the second private key, and modified nonce
    recipient_nonce[15] |= 0x01;
    let encrypted2 = cryptobox_zero_bytes(&recipient_nonce.into(), public_key2, secret_key2);

    // Combine parts of the two encrypted tokens and hash that
    let mut encrypted_buf: Vec<u8> = vec![];
    encrypted_buf.extend_from_slice(&encrypted1[32..]);
    encrypted_buf.extend_from_slice(&encrypted2[32..]);
    let mac_digest: hash::Digest = hash::sha512::hash(&encrypted_buf);
    MacKey::from_slice(&mac_digest[..32]).unwrap()
}

pub fn generate_encryption_mac_keys(
    recipients: &[PublicKey],
    header_hash: &hash::Digest,
    sender_secret_key: &SecretKey,
    ephemeral_secret_key: &SecretKey,
) -> Vec<MacKey> {
    let mut recipient_mac_keys: Vec<MacKey> = vec![];
    for (recipient_index, recipient) in recipients.iter().enumerate() {
        recipient_mac_keys.push(generate_recipient_mac_key(
            header_hash,
            recipient_index as u64,
            &recipient.clone().into(),
            &recipient.clone().into(),
            &sender_secret_key.clone().into(),
            &ephemeral_secret_key,
        ));
    }

    recipient_mac_keys
}

// Generate the recipient nonce from part of the header hash and the recipient index
fn generate_recipient_mac_nonce(header_hash: &hash::Digest, index: u64) -> Nonce {
    let mut recipient_nonce: Vec<u8> = vec![];
    recipient_nonce.extend_from_slice(&header_hash[..16]);
    recipient_nonce.write_u64::<BigEndian>(index).unwrap();

    Nonce::from_slice(&recipient_nonce).unwrap()
}

fn generate_payload_packets(
    message: &[u8],
    payload_key: &SymmetricKey,
    header_hash: &hash::Digest,
    mac_keys: &[MacKey],
) -> Vec<PayloadPacket> {
    // Output
    let mut packets: Vec<PayloadPacket> = vec![];

    // 1 MB max chunk size
    let chunk_size: usize = 1024 * 1024;
    for (index, chunk) in message.chunks(chunk_size).enumerate() {
        // Encrypt the chunk with the payload key and generated nonce
        let payload_secretbox_nonce: Nonce = generate_payload_secretbox_nonce(index as u64);
        let payload_secretbox: Vec<u8> = secretbox::seal(
            &chunk,
            &payload_secretbox_nonce.clone().into(),
            &payload_key,
        );

        // Flag if this is the final chunk
        let final_flag: bool = chunk.len() < chunk_size;

        // Authenticators for each recipient
        let authenticators: Vec<Authenticator> = generate_authenticators(
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

fn generate_authenticator_data(
    header_hash: &hash::Digest,
    payload_secretbox_nonce: &Nonce,
    final_flag: bool,
    payload_secretbox: &[u8],
) -> Vec<u8> {
    // Authenticator data is the header hash || nonce || final flag || secret box
    let mut authenticator_data: Vec<u8> = vec![];
    authenticator_data.extend_from_slice(&header_hash[..]);
    authenticator_data.extend_from_slice(&payload_secretbox_nonce.bytes());
    authenticator_data.push(final_flag as u8);
    authenticator_data.extend_from_slice(payload_secretbox);

    authenticator_data
}

fn generate_authenticators(
    header_hash: &hash::Digest,
    payload_secretbox_nonce: &Nonce,
    final_flag: bool,
    payload_secretbox: &[u8],
    mac_keys: &[MacKey],
) -> Vec<Authenticator> {
    // Authenticator data is the header hash || nonce || final flag || secret box
    let authenticator_data: Vec<u8> = generate_authenticator_data(
        header_hash,
        payload_secretbox_nonce,
        final_flag,
        payload_secretbox,
    );

    // Each authenticator is the authenticator data hashed and encrypted with the mac key
    let mut authenticators: Vec<Authenticator> = vec![];
    for key in mac_keys {
        authenticators.push(generate_authenticator(&authenticator_data, key));
    }

    authenticators
}

fn generate_authenticator(authenticator_data: &[u8], key: &MacKey) -> Authenticator {
    auth::authenticate(
        &hash::sha512::hash(&authenticator_data)[..],
        &key.clone().into(),
    )
    .into()
}

fn generate_payload_secretbox_nonce(index: u64) -> Nonce {
    let mut nonce: Vec<u8> = vec![];
    nonce.extend_from_slice(b"saltpack_ploadsb");
    nonce.write_u64::<BigEndian>(index as u64).unwrap();

    Nonce::from_slice(&nonce).unwrap()
}

pub fn create_sender_secretbox(sender: &PublicKey, payload_key: &SymmetricKey) -> Vec<u8> {
    let nonce: secretbox::Nonce =
        secretbox::Nonce::from_slice(b"saltpack_sender_key_sbox").unwrap();
    secretbox::seal(sender.as_ref(), &nonce, &payload_key)
}

pub fn open_sender_secretbox(
    secretbox: &[u8],
    payload_key: &SymmetricKey,
) -> Result<PublicKey, Error> {
    let nonce: secretbox::Nonce =
        secretbox::Nonce::from_slice(b"saltpack_sender_key_sbox").unwrap();
    if let Ok(sender_public_key) = secretbox::open(secretbox, &nonce, &payload_key) {
        return Ok(
            PublicKey::from_slice(&sender_public_key).ok_or(Error::DecryptionError(
                "Error decrypting sender secretbox".to_string(),
            ))?,
        );
    }

    Err(Error::DecryptionError(
        "Unable to decrypt sender secret box with payload key".to_string(),
    ))
}

pub fn decrypt_payload_key_for_recipient(
    public_key: &box_::PublicKey,
    secret_key: &SecretKey,
    payload_key_box_list: &[Vec<u8>],
) -> Option<Vec<u8>> {
    // Precompute the shared secret
    let key: box_::PrecomputedKey = box_::precompute(&public_key, &secret_key.clone().into());

    // Try to open each payload key box in turn
    for (recipient_index, payload_key_box) in payload_key_box_list.iter().enumerate() {
        let nonce = generate_recipient_nonce(recipient_index as u64);
        if let Ok(payload_key) = box_::open_precomputed(&payload_key_box, &nonce.into(), &key) {
            return Some(payload_key);
        }
    }

    None
}

pub fn encrypt_payload_key_for_recipient(
    recipient: &PublicKey,
    recipient_index: u64,
    payload_key: &SymmetricKey,
    secret_key: &SecretKey,
) -> Vec<u8> {
    let recipient_nonce = generate_recipient_nonce(recipient_index);
    box_::seal(
        &payload_key.0, // TODO: UGLY!!!
        &recipient_nonce.into(),
        &recipient.clone().into(),
        &secret_key,
    )
}

impl  fmt::Display for EncryptionHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Header:")?;
        writeln!(f, "  format: {}", self.format_name)?;
        writeln!(f, "  version: {}", self.version)?;
        writeln!(f, "  mode: {}", self.mode)?;
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
                    base64::encode(&recipient.public_key.as_ref().unwrap())
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

#[cfg(test)]
mod tests {
    use crate::encryption::{encrypt, EncryptionHeader};
    use crate::error::Error;
    use crate::header::Header;
    use crate::keyring::KeyRing;
    use crate::process_data::process_data;
    use crate::util::{
        generate_keypair, generate_random_public_key, generate_random_symmetric_key,
        read_base64_file,
    };
    use base64;
    use hex;
    use rmp::decode;
    use rmp_serde::{Deserializer, Serializer};
    use serde::{Deserialize, Serialize};
    use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
    use sodiumoxide::crypto::secretbox::Key as SymmetricKey;
    use sodiumoxide::crypto::{box_, scalarmult};
    use std::io::Cursor;
    use std::str;

    #[test]
    fn test_encrypt() {
        let (sender_public_key, sender_secret_key) = generate_keypair();
        let mut recipients: Vec<PublicKey> = vec![];
        for _ in 0..4 {
            recipients.push(generate_random_public_key());
        }

        let ciphertext = encrypt(
            &sender_secret_key,
            &sender_public_key,
            &recipients,
            b"Hello, World!",
        );
        println!("{}", base64::encode(&ciphertext));
        assert!(false);
    }

    fn mock_key_resolver(identifiers: &Vec<Vec<u8>>) -> Result<Vec<Option<SymmetricKey>>, Error> {
        Ok(vec![])
    }

    #[test]
    fn test_decrypt() {
        let mut data: Vec<u8> = read_base64_file("fixtures/decrypt.txt");
        let secret_key_strings = [
            "16c22cb65728ded9214c8e4525decc20f6ad95fd43a503deaecdfbcd79d39d15",
            "fceb2cb2c77b22d47a779461c7a963a11759a3f98a437d542e3cdde5d0c9bea6",
            "293d2a95a4f6ea3ed0c5213bd9b28b28ecff5c023ad488025e2a789abb773aa5",
        ];
        let secret_keys = secret_key_strings
            .iter()
            .map(|sks| hex::decode(sks).unwrap());
        let mut keyring: KeyRing = KeyRing::new();
        for secret_key_bytes in secret_keys {
            let secret_key: SecretKey = SecretKey::from_slice(&secret_key_bytes).unwrap();
            keyring.add_encryption_keys(secret_key.public_key(), secret_key);
        }

        let plaintext = process_data(&mut &data[..], &keyring, mock_key_resolver).unwrap();
        println!("{}", str::from_utf8(&plaintext).unwrap());
        assert!(false);
    }

    #[test]
    fn test_serialize_deserialize_encryption_header() {
        // Generate payload key
        let payload_key: SymmetricKey = generate_random_symmetric_key();

        // Generate ephemeral keypair
        let (ephemeral_public_key, ephemeral_secret_key) = generate_keypair();

        let sender: PublicKey = generate_random_public_key();
        let mut recipients: Vec<PublicKey> = vec![];
        for _ in 0..4 {
            recipients.push(generate_random_public_key());
        }

        let header: EncryptionHeader = EncryptionHeader::new(
            &sender,
            &recipients,
            &payload_key,
            &ephemeral_public_key,
            &ephemeral_secret_key,
        );
        println!("{}", header);

        let mut buf: Vec<u8> = vec![];
        header.serialize(&mut Serializer::new(&mut buf)).unwrap();
        println!("{:x?}", buf);
        let mut de = Deserializer::new(&buf[..]);
        let foo: EncryptionHeader = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(header, foo);
    }

    #[test]
    fn test_read_encryption_header() {
        let data: Vec<u8> = read_base64_file("fixtures/encryption.txt");
        let (_header_hash, header) = Header::decode(&mut data.as_slice()).unwrap();
        if let Header::Encryption(encryption_header) = header {
            assert_eq!(14, encryption_header.recipients_list.len());
        } else {
            assert!(false);
        }
    }
}