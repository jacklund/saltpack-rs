use crate::cryptotypes::{FromSlice, Nonce};
use crate::error::Error;
use crate::handler::Handler;
use crate::header::{Mode, Version, FORMAT_NAME, VERSION};
use crate::keyring::KeyRing;
use crate::process_data::{DecryptedResult, KeyResolver};
use crate::util::{
    cryptobox_zero_bytes, generate_header_packet, generate_keypair, generate_random_symmetric_key,
    generate_recipient_nonce,
};
use base64;
use byteorder::{BigEndian, WriteBytesExt};
use hmac::{Hmac, Mac};
use rand::seq::SliceRandom;
use rand::thread_rng;
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use serde_bytes;
use sha2::Sha512;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
use sodiumoxide::crypto::secretbox::Key as SymmetricKey;
use sodiumoxide::crypto::sign::PublicKey as PublicSigningKey;
use sodiumoxide::crypto::sign::SecretKey as SigningKey;
use sodiumoxide::crypto::{hash, secretbox, sign};
use std::fmt;
use std::io::Read;

type HmacSha512 = Hmac<Sha512>;

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
    version: Version,
    mode: Mode,
    public_key: PublicKey,
    #[serde(with = "serde_bytes")]
    sender_secretbox: Vec<u8>,
    recipients_list: Vec<SigncryptionRecipientPair>,
}

const BOX_HMAC_KEY: &[u8] = b"saltpack signcryption box key identifier";
const SYMMETRIC_HMAC_KEY: &[u8] = b"saltpack signcryption derived symmetric key";

impl SigncryptionHeader {
    pub fn new(
        public_signing_key: &PublicSigningKey,
        recipient_public_keys: &[PublicKey],
        recipient_symmetric_keys: &[ReceiverSymmetricKey],
        payload_key: &SymmetricKey,
        ephemeral_public_key: &PublicKey,
        ephemeral_secret_key: &SecretKey,
    ) -> Self {
        let sender_secretbox = secretbox::seal(
            &public_signing_key[..],
            &secretbox::Nonce::from_slice(b"saltpack_sender_key_sbox").unwrap(),
            &payload_key,
        );

        // Combine the keys so we can shuffle them all
        // Can't use anything with an iterator, because we'd need to
        // implement FromIterator, which we can't for PublicKey
        let mut recipient_keys: Vec<Box<RecipientKey>> = vec![];
        for key in recipient_public_keys {
            recipient_keys.push(Box::new(*key));
        }
        for key in recipient_symmetric_keys {
            recipient_keys.push(Box::new(key.clone()));
        }

        let mut rng = thread_rng();
        recipient_keys.shuffle(&mut rng);

        let mut recipients_list: Vec<SigncryptionRecipientPair> = vec![];
        for (index, key) in recipient_keys.iter().enumerate() {
            recipients_list.push(key.generate_id_and_box(
                &payload_key,
                &ephemeral_public_key,
                &ephemeral_secret_key,
                index,
            ));
        }

        SigncryptionHeader {
            format_name: FORMAT_NAME.to_string(),
            version: VERSION,
            mode: Mode::Signcryption,
            public_key: *ephemeral_public_key,
            sender_secretbox,
            recipients_list,
        }
    }

    pub fn get_handler(
        &self,
        header_hash: hash::Digest,
        keyring: &KeyRing,
        resolver: KeyResolver,
    ) -> Result<Box<Handler>, Error> {
        // Try to decrypt the payload key using the secret keys; if that fails, try
        // the symmetric keys; if that fails, raise an error
        let payload_key = self
            .try_secret_keys(keyring)
            .transpose()
            .unwrap_or_else(|| {
                self.try_symmetric_keys(resolver).transpose().unwrap_or(Err(
                    Error::DecryptionError("No key found to decrypt message".to_string()),
                ))
            })?;

        let sender_signing_key_bytes: Vec<u8> = secretbox::open(
            &self.sender_secretbox,
            &secretbox::Nonce::from_slice(b"saltpack_sender_key_sbox").unwrap(),
            &payload_key,
        )
        .map_err(|_| Error::DecryptionError("Error decrypting sender secretbox".to_string()))?;

        Ok(Box::new(SigncryptionHandler::new(
            payload_key,
            PublicSigningKey::from_slice(&sender_signing_key_bytes).unwrap(),
            header_hash,
        )))
    }

    fn generate_derived_box_key(&self, secret_key: &SecretKey) -> Result<SymmetricKey, Error> {
        let key_data: Vec<u8> = cryptobox_zero_bytes(
            &Nonce::from_slice(&"saltpack_derived_sboxkey".as_bytes()).unwrap(),
            &self.public_key,
            &secret_key,
        )
        .iter()
        .skip(16)
        .map(|&byte| byte)
        .collect::<Vec<u8>>();

        SymmetricKey::from_slice(&key_data)
            .ok_or(Error::KeyLengthError(secretbox::KEYBYTES, key_data.len()))
    }

    fn try_secret_keys(&self, keyring: &KeyRing) -> Result<Option<SymmetricKey>, Error> {
        for secret_key in keyring.get_all_encryption_keys() {
            let derived_symmetric_key: SymmetricKey = self.generate_derived_box_key(&secret_key)?;
            for (index, recipient) in self.recipients_list.iter().enumerate() {
                let nonce = generate_recipient_nonce(index as u64);
                let identifier: Vec<u8> = generate_identifier(&derived_symmetric_key, &nonce);
                if recipient.recipient_id == identifier {
                    if let Ok(payload_key_data) = secretbox::open(
                        &recipient.payload_key_box,
                        &nonce.into(),
                        &derived_symmetric_key,
                    ) {
                        return Ok(Some(SymmetricKey::from_slice(&payload_key_data).unwrap()));
                    }
                }
            }
        }

        Ok(None)
    }

    fn try_symmetric_keys(&self, resolver: KeyResolver) -> Result<Option<SymmetricKey>, Error> {
        let identifiers: Vec<Vec<u8>> = self
            .recipients_list
            .iter()
            .map(|recip| recip.recipient_id.clone())
            .collect();
        let keys: Vec<Option<SymmetricKey>> = resolver(&identifiers)?;
        if keys.len() != identifiers.len() {
            println!(
                "Found {} keys and {} identifiers",
                keys.len(),
                identifiers.len()
            );
            return Err(Error::ResolverError(
                "Wrong number of keys resolved".to_string(),
            ));
        }
        for (index, opt_key) in keys.iter().enumerate() {
            if let Some(key) = opt_key {
                let derived_key = generate_derived_symmetric_key(&self.public_key, &key);
                let nonce = generate_recipient_nonce(index as u64);
                if let Ok(payload_key_data) = secretbox::open(
                    &self.recipients_list[index].payload_key_box,
                    &nonce.into(),
                    &derived_key,
                ) {
                    return Ok(Some(SymmetricKey::from_slice(&payload_key_data).unwrap()));
                }
            }
        }

        Ok(None)
    }
}

impl fmt::Display for SigncryptionHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Header:")?;
        writeln!(f, "  format: {}", self.format_name)?;
        writeln!(f, "  version: {}", self.version)?;
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
    pub sender_signing_key: PublicSigningKey,
    pub header_hash: hash::Digest,
}

impl SigncryptionHandler {
    pub fn new(
        payload_key: SymmetricKey,
        sender_signing_key: PublicSigningKey,
        header_hash: hash::Digest,
    ) -> SigncryptionHandler {
        SigncryptionHandler {
            payload_key,
            sender_signing_key,
            header_hash,
        }
    }

    fn process_packet(
        &self,
        packet: &PayloadPacket,
        packet_index: usize,
    ) -> Result<Vec<u8>, Error> {
        let packet_nonce: Nonce =
            generate_packet_nonce(packet_index, packet.final_flag, &self.header_hash);
        let decrypted: Vec<u8> = self.decrypt_packet(packet, &packet_nonce)?;
        let signature: Vec<u8> = decrypted[..64].to_vec();
        let plaintext: Vec<u8> = decrypted[64..].to_vec();
        if self.sender_signing_key[..].iter().any(|b| *b != 0) {
            let signature_input: Vec<u8> = generate_signature_input(
                &self.header_hash,
                &packet_nonce,
                packet.final_flag,
                &hash::sha512::hash(&plaintext),
            );
            if !sign::verify_detached(
                &sign::Signature::from_slice(&signature).unwrap(),
                &signature_input,
                &self.sender_signing_key,
            ) {
                return Err(Error::AuthenticationError("Signature mismatch".to_string()));
            }
        }
        Ok(plaintext)
    }

    fn decrypt_packet(
        &self,
        packet: &PayloadPacket,
        packet_nonce: &Nonce,
    ) -> Result<Vec<u8>, Error> {
        secretbox::open(
            &packet.signcrypted_chunk,
            &packet_nonce.into(),
            &self.payload_key,
        )
        .map_err(|_| Error::DecryptionError("Error decrypting signcrypted chunk".to_string()))
    }
}

impl Handler for SigncryptionHandler {
    fn process_payload(&self, reader: &mut Read) -> Result<DecryptedResult, Error> {
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

        Ok(DecryptedResult::SignCryption {
            plaintext: ret,
            sender_public_key: self.sender_signing_key,
        })
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct PayloadPacket {
    #[serde(with = "serde_bytes")]
    signcrypted_chunk: Vec<u8>,
    final_flag: bool,
}

#[derive(Clone)]
pub struct ReceiverSymmetricKey {
    identifer: Vec<u8>,
    key: SymmetricKey,
}

trait RecipientKey {
    fn generate_id_and_box(
        &self,
        payload_key: &SymmetricKey,
        ephemeral_public_key: &PublicKey,
        ephemeral_secret_key: &SecretKey,
        index: usize,
    ) -> SigncryptionRecipientPair;
}

impl RecipientKey for PublicKey {
    fn generate_id_and_box(
        &self,
        payload_key: &SymmetricKey,
        _ephemeral_public_key: &PublicKey,
        ephemeral_secret_key: &SecretKey,
        index: usize,
    ) -> SigncryptionRecipientPair {
        let key_bytes: Vec<u8> = cryptobox_zero_bytes(
            &Nonce::from_slice(b"saltpack_derived_sboxkey").unwrap(),
            self,
            ephemeral_secret_key,
        );
        let shared_key: SymmetricKey =
            SymmetricKey::from_slice(&key_bytes[(key_bytes.len() - 32)..]).unwrap();
        let recipient_nonce: Nonce = generate_recipient_nonce(index as u64);
        let payload_key_box: Vec<u8> =
            secretbox::seal(&payload_key[..], &recipient_nonce.into(), &shared_key);
        let recipient_id: Vec<u8> = generate_identifier(&shared_key, &recipient_nonce);

        SigncryptionRecipientPair {
            recipient_id,
            payload_key_box,
        }
    }
}

fn generate_derived_symmetric_key(
    public_key: &PublicKey,
    symmetric_key: &SymmetricKey,
) -> SymmetricKey {
    let mut combined: Vec<u8> = vec![];
    combined.extend(public_key.as_ref());
    combined.extend(&symmetric_key[..]);
    let mut hmac = HmacSha512::new_varkey(SYMMETRIC_HMAC_KEY).unwrap();
    hmac.input(&combined);
    let mac = hmac.result();
    SymmetricKey::from_slice(&mac.code()[..32]).unwrap()
}

fn generate_identifier(derived_symmetric_key: &SymmetricKey, nonce: &Nonce) -> Vec<u8> {
    let mut combined: Vec<u8> = derived_symmetric_key[..].to_vec();
    combined.extend(nonce.bytes());
    let mut hmac = HmacSha512::new_varkey(&BOX_HMAC_KEY).unwrap();
    hmac.input(&combined);
    let mac = hmac.result();
    mac.code()[..32].to_vec()
}

impl RecipientKey for ReceiverSymmetricKey {
    fn generate_id_and_box(
        &self,
        payload_key: &SymmetricKey,
        ephemeral_public_key: &PublicKey,
        _ephemeral_secret_key: &SecretKey,
        index: usize,
    ) -> SigncryptionRecipientPair {
        // Hash the ephemeral_public_key and symmetric key
        // to make a shared key
        let mut key_bytes: Vec<u8> = ephemeral_public_key[..].to_vec();
        key_bytes.extend(&self.key[..]);
        let shared_key: SymmetricKey =
            generate_derived_symmetric_key(&ephemeral_public_key, &self.key);
        let recipient_nonce: Nonce = generate_recipient_nonce(index as u64);
        let payload_key_box: Vec<u8> =
            secretbox::seal(&payload_key[..], &recipient_nonce.into(), &shared_key);

        SigncryptionRecipientPair {
            recipient_id: self.identifer.clone(),
            payload_key_box,
        }
    }
}

pub fn signcrypt(
    signing_key: &SigningKey,
    public_signing_key: &PublicSigningKey,
    recipient_public_keys: &[PublicKey],
    recipient_symmetric_keys: &[ReceiverSymmetricKey],
    message: &[u8],
) -> Vec<u8> {
    // Generate payload key
    let payload_key: SymmetricKey = generate_random_symmetric_key();

    // Generate ephemeral keypair
    let (ephemeral_public_key, ephemeral_secret_key) = generate_keypair();

    let header: SigncryptionHeader = SigncryptionHeader::new(
        &public_signing_key,
        recipient_public_keys,
        recipient_symmetric_keys,
        &payload_key,
        &ephemeral_public_key,
        &ephemeral_secret_key,
    );

    // Generate header packet and header hash
    let (header_hash, header_packet) = generate_header_packet(&header);

    let payload_packets: Vec<PayloadPacket> =
        generate_payload_packets(message, signing_key, &payload_key, &header_hash);

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

fn generate_payload_packets(
    message: &[u8],
    signing_key: &SigningKey,
    payload_key: &SymmetricKey,
    header_hash: &hash::Digest,
) -> Vec<PayloadPacket> {
    // Output
    let mut packets: Vec<PayloadPacket> = vec![];

    // 1 MB max chunk size
    let chunk_size: usize = 1024 * 1024;
    for (index, chunk) in message.chunks(chunk_size).enumerate() {
        // Flag if this is the final chunk
        let final_flag: bool = chunk.len() < chunk_size;

        let packet_nonce: Nonce = generate_packet_nonce(index, final_flag, header_hash);

        let signature_input: Vec<u8> = generate_signature_input(
            header_hash,
            &packet_nonce,
            final_flag,
            &hash::sha512::hash(message),
        );

        let generated_signature = sign::sign_detached(&signature_input, &signing_key)[..].to_vec();
        let mut chunk_to_encrypt: Vec<u8> = generated_signature;
        chunk_to_encrypt.extend(message);

        let signcrypted_chunk: Vec<u8> =
            secretbox::seal(&chunk_to_encrypt, &packet_nonce.into(), payload_key);

        packets.push(PayloadPacket {
            signcrypted_chunk,
            final_flag,
        });
    }

    packets
}

fn generate_packet_nonce(
    packet_index: usize,
    final_flag: bool,
    header_hash: &hash::Digest,
) -> Nonce {
    let mut nonce_data: Vec<u8> = vec![];
    nonce_data.extend(&header_hash[..16]);
    if final_flag {
        nonce_data[15] |= 0x01;
    } else {
        nonce_data[15] &= 0xfe;
    }
    nonce_data
        .write_u64::<BigEndian>(packet_index as u64)
        .unwrap();

    Nonce::from_slice(&nonce_data).unwrap()
}

fn generate_signature_input(
    header_hash: &hash::Digest,
    packet_nonce: &Nonce,
    final_flag: bool,
    plaintext_hash: &hash::Digest,
) -> Vec<u8> {
    let mut signature_input: Vec<u8> = vec![];
    signature_input.extend(b"saltpack encrypted signature");
    signature_input.push(0x0);
    signature_input.extend(header_hash.as_ref());
    signature_input.extend(&packet_nonce.bytes());
    if final_flag {
        signature_input.push(0x1);
    } else {
        signature_input.push(0x0);
    }
    signature_input.extend(plaintext_hash.as_ref());

    signature_input
}

#[cfg(test)]
mod tests {
    use crate::error::Error;
    use crate::header::Header;
    use crate::keyring::KeyRing;
    use crate::process_data::{process_data, DecryptedResult};
    use crate::signcryption::signcrypt;
    use crate::util::{
        generate_keypair, generate_signing_keypair, read_base64_file, read_signing_keys_and_data,
    };
    use sodiumoxide::crypto::box_::PublicKey;
    use sodiumoxide::crypto::secretbox::Key as SymmetricKey;
    use std::str;

    fn mock_key_resolver(_identifiers: &Vec<Vec<u8>>) -> Result<Vec<Option<SymmetricKey>>, Error> {
        Ok(vec![])
    }

    #[test]
    fn test_read_signcryption_header() {
        let data: Vec<u8> = read_base64_file("fixtures/signcryption_header.txt");
        let (_header_hash, header) = Header::decode(&mut data.as_slice()).unwrap();
        if let Header::Signcryption(signcryption_header) = header {
            assert_eq!(15, signcryption_header.recipients_list.len());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_signcrypt() {
        let (public_signing_key, signing_key) = generate_signing_keypair();
        let mut recipients: Vec<PublicKey> = vec![];
        let mut keyring: KeyRing = KeyRing::new();
        for _ in 0..4 {
            let (public_key, secret_key) = generate_keypair();
            recipients.push(public_key);
            keyring.add_encryption_keys(public_key, secret_key);
        }

        let signcrypted: Vec<u8> = signcrypt(
            &signing_key,
            &public_signing_key,
            &recipients,
            &vec![],
            b"Hello, World!",
        );
        match process_data(&mut &signcrypted[..], &keyring, mock_key_resolver).unwrap() {
            DecryptedResult::SignCryption {
                plaintext,
                sender_public_key,
            } => assert_eq!("Hello, World!", str::from_utf8(&plaintext).unwrap()),
            _ => assert!(false),
        }
    }

    #[test]
    fn test_signcryption_interoperability() {
        // Fixture is data generated from the Go Saltpack library test
        // 'TestSigncryptionBoxKeyHelloWorld'
        let (public_key, secret_key, _public_signing_key, _signing_key, data) =
            read_signing_keys_and_data("fixtures/signcryption.txt");
        let mut recipients: Vec<PublicKey> = vec![];
        recipients.push(public_key);
        let mut keyring: KeyRing = KeyRing::new();
        keyring.add_encryption_keys(public_key, secret_key);
        match process_data(&mut &data[..], &keyring, mock_key_resolver).unwrap() {
            DecryptedResult::SignCryption {
                plaintext,
                sender_public_key,
            } => assert_eq!("hello world", str::from_utf8(&plaintext).unwrap()),
            _ => assert!(false),
        }
    }
}
