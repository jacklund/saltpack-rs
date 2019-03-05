use crate::error::Error;
use sodiumoxide::crypto::{auth, box_, scalarmult, secretbox};
use std::convert::From;
use std::ops::{Index, IndexMut};

// Various cryptography types
//
// These are basically just wrappers around the raw bytes. This allows us
// to know what each thing is, semantically, as we pass it around, plus
// it gives us some important length/type checking
//
// We have a macro to do the heavy lifting, plus converters to allow us to
// convert from our types to those required by sodiumoxide. We _could_ have
// just used the sodiumoxide types, but that would have exposed that library
// at a higher level than I would like. The conversions are basically zero-cost
// anyway.

pub trait FromSlice<T> {
    fn from_slice(data: &[u8]) -> Result<T, Error>;
}

#[macro_export]
macro_rules! cryptotype {
    ( $x:ident, $l:expr ) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
        pub struct $x(pub [u8; $l]);

        impl $x {
            pub fn bytes(&self) -> Vec<u8> {
                self.0.to_vec()
            }
        }

        impl crate::cryptotypes::FromSlice<$x> for $x {
            fn from_slice(data: &[u8]) -> Result<Self, Error> {
                if data.len() != $l {
                    Err(Error::KeyLengthError(format!(
                        "Expected length {}, found length {}",
                        $l,
                        data.len()
                    )))
                } else {
                    let mut key_data: [u8; $l] = [0; $l];
                    key_data.copy_from_slice(data);
                    Ok($x(key_data))
                }
            }
        }

        impl std::convert::AsRef<[u8]> for $x {
            fn as_ref(&self) -> &[u8] {
                &self.0[..]
            }
        }
    };
}

// Authenticator
cryptotype!(Authenticator, 32);

// Public Key
cryptotype!(PublicKey, 32);

impl From<scalarmult::GroupElement> for PublicKey {
    fn from(ge: scalarmult::GroupElement) -> PublicKey {
        PublicKey(ge.0)
    }
}

// Secret Key
cryptotype!(SecretKey, 32);

// MAC
cryptotype!(MacKey, 32);

// Symmetric Key
cryptotype!(SymmetricKey, 32);

// Nonce
cryptotype!(Nonce, 24);

// Convert from auth::Tag to Authenticator
impl From<auth::Tag> for Authenticator {
    fn from(tag: auth::Tag) -> Authenticator {
        Authenticator(tag.0)
    }
}

// Convert from MacKey to auth::Key
impl From<MacKey> for auth::Key {
    fn from(key: MacKey) -> auth::Key {
        auth::Key(key.0)
    }
}

// Convert from Nonce to box_::Nonce
impl From<Nonce> for box_::Nonce {
    fn from(nonce: Nonce) -> box_::Nonce {
        box_::Nonce(nonce.0)
    }
}

// Convert from Nonce to secretbox::Nonce
impl From<Nonce> for secretbox::Nonce {
    fn from(nonce: Nonce) -> secretbox::Nonce {
        secretbox::Nonce(nonce.0)
    }
}

// Index into a Nonce immutably
impl Index<usize> for Nonce {
    type Output = u8;

    fn index(&self, index: usize) -> &u8 {
        &self.0[index]
    }
}

// Index into a Nonce mutably
impl IndexMut<usize> for Nonce {
    fn index_mut(&mut self, index: usize) -> &mut u8 {
        &mut self.0[index]
    }
}

// Convert from a PublicKey to a box_::PublicKey
impl From<PublicKey> for box_::PublicKey {
    fn from(key: PublicKey) -> box_::PublicKey {
        box_::PublicKey(key.0)
    }
}

// Convert from a box_::PublicKey to a PublicKey
impl From<box_::PublicKey> for PublicKey {
    fn from(key: box_::PublicKey) -> PublicKey {
        PublicKey(key.0)
    }
}

// Convert from a SecretKey to a box_::SecretKey
impl From<SecretKey> for box_::SecretKey {
    fn from(key: SecretKey) -> box_::SecretKey {
        box_::SecretKey(key.0)
    }
}

// Convert from a box_::SecretKey to a SecretKey
impl From<box_::SecretKey> for SecretKey {
    fn from(key: box_::SecretKey) -> SecretKey {
        SecretKey(key.0)
    }
}

impl From<SecretKey> for scalarmult::Scalar {
    fn from(sk: SecretKey) -> scalarmult::Scalar {
        scalarmult::Scalar(sk.0)
    }
}

impl From<&SecretKey> for scalarmult::Scalar {
    fn from(sk: &SecretKey) -> scalarmult::Scalar {
        scalarmult::Scalar(sk.0)
    }
}

// Convert from a SymmetricKey to a secretbox::Key
impl From<&SymmetricKey> for secretbox::Key {
    fn from(key: &SymmetricKey) -> secretbox::Key {
        secretbox::Key(key.0)
    }
}

// Convert from a SymmetricKey to a secretbox::Key
impl From<SymmetricKey> for secretbox::Key {
    fn from(key: SymmetricKey) -> secretbox::Key {
        secretbox::Key(key.0)
    }
}
