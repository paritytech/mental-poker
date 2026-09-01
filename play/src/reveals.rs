
// use cards_protocol::IntoTranscript;

use crate::*;

use ark_serialize::{CanonicalSerialize,CanonicalDeserialize,SerializationError,Compress,Validate,Valid};
#[cfg(feature="wasm")]
use ez_serialize::EzSerialize;
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
    fn from(s: CompressedChecked<AccumulateReveals>) -> Self { s.0 }
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
    fn check(&self) -> Result<(), SerializationError> { self.0.check() }
}

impl AccumulateReveals {
    #[cfg(feature="prover")]
    pub fn prove_reveal(
        &self,
        sk: &PlayerKeypair,
    ) -> RevealMessage {
        self.0.prove_reveal(&mut getrandom_or_panic(), sk)
    }

    pub fn add_reveal(&mut self, reveal_message: &RevealMessage) -> CardResult<()> {
        self.0.add_reveal(reveal_message)
    }
}

#[cfg_attr(feature="wasm", wasm_bindgen)]
impl AccumulateReveals {
    pub fn is_completed(&self) -> bool { self.0.is_completed() }
}

#[cfg(feature="wasm")]
#[wasm_bindgen]
impl AccumulateReveals {
    #[cfg(feature="prover")]
    #[wasm_bindgen(js_name="prove_reveal")]
    pub fn prove_reveal_wasm(
        &self,
        sk: &PlayerKeypairWasm,
    ) -> Vec<u8> /* RevealMessage */ {
        self.prove_reveal(&sk.0).serialize_to_vec().unwrap()
    }

    #[wasm_bindgen(js_name="add_reveal")]
    pub fn add_reveal_wasm(&mut self, reveal_message: &[u8]) -> wasm::ResultWasm<()> {
        let reveal_message = RevealMessage::deserialize_compressed(reveal_message) ?;
        Ok(self.add_reveal(&reveal_message)?)
    }

    #[wasm_bindgen(js_name="deserialize")]
    pub fn wasm_deserialize(selfy: &[u8]) -> wasm::ResultWasm<AccumulateReveals> {
        Ok(AccumulateReveals::deserialize_compressed(selfy) ?)
    }

    #[wasm_bindgen(js_name="serialize")]
    pub fn wasm_serialize(&self) -> Vec<u8> {
        self.serialize_to_vec().unwrap()
    }

    /// Unmask the card (once all reveals are accumulated) and return its deck position.
    pub fn completed_position(&self) -> wasm::ResultWasm<usize> {
        let unmasked = self.0.completed().ok_or("Card not yet fully revealed")?;
        wasm::card_position(&unmasked)
    }
}
