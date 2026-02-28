
// use cards_protocol::IntoTranscript;

use crate::*;

use ark_serialize::{CanonicalSerialize,CanonicalDeserialize,SerializationError,Compress,Validate,Valid,CompressedChecked};
#[cfg(feature="serde")]
use serde::{Serialize, Deserialize};

type AccInner = cards_protocol::reveal::AccumulateReveals<'static, Curve>;

#[derive(Clone,CanonicalSerialize)]
#[cfg_attr(feature="serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature="serde", serde(from = "CompressedChecked<Self>", into = "CompressedChecked<Self>"))]
#[repr(transparent)]
pub struct AccumulateReveals(
    pub AccInner
);

impl core::ops::Deref for AccumulateReveals {
    type Target = AccInner;
    fn deref(&self) -> &Self::Target { &self.0}
}
impl From<CompressedChecked<AccumulateReveals>> for AccumulateReveals {
    fn from(sig: CompressedChecked<AccumulateReveals>) -> Self { sig.0 }
}
impl CanonicalDeserialize for AccumulateReveals {
    fn deserialize_with_mode<R: ark_std::io::Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        Ok(AccumulateReveals(AccInner::deserialize_with_mode(reader,compress,validate,PARAMS) ?))
    }
}
impl Valid for AccumulateReveals {
    fn check(&self) -> Result<(), SerializationError> {
        self.0.check()
    }
}

impl AccumulateReveals {
    pub fn add_reveal(&mut self, reveal_message: &RevealMessage) -> Result<(), CardProtocolError> {
        self.0.add_reveal(reveal_message)
    }
    
    // pub fn completed or similar?    
}
