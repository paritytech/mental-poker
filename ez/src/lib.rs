
pub use ark_std::io::{Read, Write};
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};

// #[cfg(feature="wasm")]
// mod wasm;


pub trait EzDeserialize : CanonicalDeserialize {
    fn deserialize<R: Read>(r: R) -> Result<Self, SerializationError> {
        Self::deserialize_compressed(r)
    }
}

impl<T: CanonicalDeserialize> EzDeserialize for T { }

pub trait EzSerialize : CanonicalSerialize {
    fn serialized_len(&self) -> usize { self.compressed_size() }
    fn serialize<W: Write>(&self, w: W) -> Result<(), SerializationError>
        { self.serialize_compressed(w) }

    fn serialize_to_vec(&self) -> Result<Vec<u8>, SerializationError> {
        let size_hint = self.serialized_len();
        let mut v: Vec<u8> = Vec::with_capacity(size_hint);
        self.serialize(&mut v)?;
        Ok(v)
    }
}

impl<T: CanonicalSerialize> EzSerialize for T { }

