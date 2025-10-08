
pub use ark_std::io::{Read, Write};
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};

pub trait EzDeserialize : CanonicalDeserialize {
    fn read_deserialized<R: Read>(r: R) -> Result<Self, SerializationError>;
}

impl<T: CanonicalDeserialize> EzDeserialize for T {
    fn read_deserialized<R: Read>(r: R) -> Result<T, SerializationError> {
        T::deserialize_compressed(r)
    }
}

pub trait EzSerialize : CanonicalSerialize {
    fn serialized_len(&self) -> usize;
    fn write_serialized<W: Write>(&self, w: W) -> Result<(), SerializationError>;

    fn serialize_to_vec(&self, size_hint: Option<usize>) -> Result<Vec<u8>, SerializationError> {
        let size_hint = size_hint.unwrap_or(self.serialized_len());
        let mut v: Vec<u8> = Vec::with_capacity(size_hint);
        self.write_serialized(&mut v)?;
        Ok(v)
    }
}

impl<T: CanonicalSerialize> EzSerialize for T {
    fn serialized_len(&self) -> usize { self.compressed_size() }
    fn write_serialized<W: Write>(&self, w: W) -> Result<(), SerializationError>
        { self.serialize_compressed(w) }
}

