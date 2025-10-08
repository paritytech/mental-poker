//! We deserialize several types in cards-protocol that require our
//! `&Parameters`, which itself winds up too large to  serialized often.
//! We add specialized deserialization here that assumes our specific
//! `PARAMS: &'static Parameters`.
//!
//! We're forbidden by the orphan rules from directly implementing the
//! traits from `ark_serialize` or `ex_serialize`, barring some future
//! stabilization or specialized or `#[fundamental]` or similar.
//!
//! We'd circumvent the orphan rules by doing dependency injection with
//! type parameters, or simply wrapper types, if we really cared about
//! serialization being trait based here.   Instead, these types all live
//! high enough up the hierarchy that inherent methods suffice, which
//! as a bonus resemble the `ex_serialize` trait methods.

use ark_std::io::{Read, Write};

pub use ez_serialize::{EzDeserialize, EzSerialize, SerializationError};

use crate::*;

pub trait MyDeserialize: Sized {
    fn read_deserialized<R: Read>(r: R) -> Result<Self, SerializationError>;
}

pub trait MySerialize {
    fn serialized_len(&self) -> usize;
    fn write_serialized<W: Write>(&self, w: W) -> Result<(), SerializationError>;

    fn serialize_to_vec(&self, size_hint: Option<usize>) -> Result<Vec<u8>, SerializationError> {
        let size_hint = size_hint.unwrap_or(self.serialized_len());
        let mut v: Vec<u8> = Vec::with_capacity(size_hint);
        self.write_serialized(&mut v)?;
        Ok(v)
    }
}

// cards_protocol::keys

impl MyDeserialize for AggregatedPublicKeys {
    fn read_deserialized<R: Read>(r: R) -> Result<AggregatedPublicKeys, SerializationError> {
        AggregatedPublicKeys::deserialize(r, PARAMS)
    }
}
impl MySerialize for AggregatedPublicKeys {
    fn serialized_len(&self) -> usize {
        self.serialized_size()
    }
    fn write_serialized<W: Write>(&self, w: W) -> Result<(), SerializationError> {
        self.serialize(w)
    }
}

// cards_protocol::reveal

impl MyDeserialize for AccumulateReveals {
    fn read_deserialized<R: Read>(r: R) -> Result<AccumulateReveals, SerializationError> {
        AccumulateReveals::deserialize(r, PARAMS)
    }
}
impl MySerialize for AccumulateReveals {
    fn serialized_len(&self) -> usize {
        self.serialized_size()
    }
    fn write_serialized<W: Write>(&self, w: W) -> Result<(), SerializationError> {
        self.serialize(w)
    }
}

