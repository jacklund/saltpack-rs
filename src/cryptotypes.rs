use crate::error::Error;
use sodiumoxide::crypto::{auth, box_, hash, secretbox};
use std;
use std::convert::From;
use std::fmt;
use std::ops::{Index, IndexMut};

// Various cryptography types
//
// These are basically just wrappers around the raw bytes. This allows us
// to know what each thing is, semantically, as we pass it around, plus
// it gives us some important length/type checking
//
// We have a macro to do the heavy lifting, plus converters to allow us to
// convert from our types to those required by sodiumoxide. We use the sodiumoxide
// types otherwise, since they work especially well with serde.

pub trait FromSlice<T> {
    fn from_slice(data: &[u8]) -> Result<T, Error>;
}

// Define crypto types. Note: (de)serialization code borrowed from sodiumoxide
#[macro_export]
macro_rules! cryptotype {
    ( $x:ident, $l:expr ) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $x(pub [u8; $l]);

        impl ::serde::Serialize for $x {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                serializer.serialize_bytes(&self.0[..])
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $x {
            fn deserialize<D>(deserializer: D) -> Result<$x, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                struct NewtypeVisitor;
                impl<'de> ::serde::de::Visitor<'de> for NewtypeVisitor {
                    type Value = $x;
                    fn expecting(
                        &self,
                        formatter: &mut ::std::fmt::Formatter,
                    ) -> ::std::fmt::Result {
                        write!(formatter, stringify!($x))
                    }
                    fn visit_seq<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
                    where
                        V: ::serde::de::SeqAccess<'de>,
                    {
                        let mut res = $x([0; $l]);
                        for r in res.0.iter_mut() {
                            if let Some(value) = visitor.next_element()? {
                                *r = value;
                            }
                        }
                        Ok(res)
                    }
                    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                    where
                        E: ::serde::de::Error,
                    {
                        $x::from_slice(v)
                            .map_err(|_| ::serde::de::Error::invalid_length(v.len(), &self))
                    }
                }
                deserializer.deserialize_bytes(NewtypeVisitor)
            }
        }

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

// Have to implement this by hand because the derives for [u8; $x] only
// go up to $x <= 32 ¯\_(ツ)_/¯
#[derive(Clone)]
pub struct Hash(pub [u8; 64]);

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&&self.0[..], f)
    }
}

impl Eq for Hash {}

impl PartialEq for Hash {
    #[inline]
    fn eq(&self, other: &Hash) -> bool {
        self.0[..] == other.0[..]
    }
    #[inline]
    fn ne(&self, other: &Hash) -> bool {
        self.0[..] != other.0[..]
    }
}

impl std::hash::Hash for Hash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&self.0[..], state)
    }
}

// Authenticator
cryptotype!(Authenticator, 32);

// MAC
cryptotype!(MacKey, 32);

// Nonce
cryptotype!(Nonce, 24);

// Hash
// cryptotype!(Hash, 64);

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

// Convert from &MacKey to auth::Key
impl From<&MacKey> for auth::Key {
    fn from(key: &MacKey) -> auth::Key {
        auth::Key(key.0)
    }
}

// Convert from Nonce to box_::Nonce
impl From<Nonce> for box_::Nonce {
    fn from(nonce: Nonce) -> box_::Nonce {
        box_::Nonce(nonce.0)
    }
}

// Convert from &Nonce to box_::Nonce
impl From<&Nonce> for box_::Nonce {
    fn from(nonce: &Nonce) -> box_::Nonce {
        box_::Nonce(nonce.0)
    }
}

// Convert from Nonce to secretbox::Nonce
impl From<Nonce> for secretbox::Nonce {
    fn from(nonce: Nonce) -> secretbox::Nonce {
        secretbox::Nonce(nonce.0)
    }
}

// Convert from &Nonce to secretbox::Nonce
impl From<&Nonce> for secretbox::Nonce {
    fn from(nonce: &Nonce) -> secretbox::Nonce {
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

// Convert from a Hash to a hash::Digest
impl From<Hash> for hash::Digest {
    fn from(hash: Hash) -> hash::Digest {
        hash::Digest(hash.0)
    }
}
