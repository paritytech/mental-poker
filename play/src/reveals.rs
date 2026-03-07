
// use cards_protocol::IntoTranscript;

use crate::*;

use ark_serialize::{CanonicalSerialize,CanonicalDeserialize,SerializationError,Compress,Validate,Valid};
#[cfg(feature="serde")]
use ark_serialize::{CompressedChecked};
#[cfg(feature="serde")]
use serde::{Serialize, Deserialize};

// #[cfg(feature="wasm")]
// use wasm_bindgen::prelude::*;


type AccInner = cards_protocol::reveal::AccumulateReveals<'static, Curve>;

#[derive(Clone,CanonicalSerialize)]
#[cfg_attr(feature="serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature="serde", serde(from = "CompressedChecked<Self>", into = "CompressedChecked<Self>"))]
#[repr(transparent)]
#[cfg_attr(feature="wasm", wasm_bindgen)]
pub struct AccumulateReveals(pub(crate) AccInner);

impl core::ops::Deref for AccumulateReveals {
    type Target = AccInner;
    fn deref(&self) -> &Self::Target { &self.0}
}
impl core::ops::DerefMut for AccumulateReveals {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0}    
}
#[cfg(feature="serde")]
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
}

#[cfg(feature="wasm")]
#[wasm_bindgen]
impl AccumulateReveals {
    pub fn add_reveal_wasm(&mut self, reveal_message: &[u8]) -> Result<(), crate::wasm::CardsErrorWasm> {
        let reveal_message = cards_protocol::RevealMessage::deserialize_compressed(reveal_message) ?;
        Ok(self.add_reveal(&reveal_message)?)
    }

    // pub fn completed or similar?    
}
