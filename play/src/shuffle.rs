
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

impl AggregatedPublicKeys {
    /// Shuffle cards and produce proof using system randomness
    ///
    /// Verified using `verify_shuffle`
    #[cfg(feature="prover")]
    pub fn shuffle_and_remask(
        &self, sk: &PlayerKeypair, deck: &[MaskedCard],
    ) -> CardResult<ShuffleMessage> {
        self.0.shuffle_and_remask(&mut getrandom_or_panic(), sk, deck)
    }

    pub fn accumulate_shuffles(self, deck: Vec<MaskedCard>) -> AccumulateShuffles {
        AccumulateShuffles(self.0.accumulate_shuffles(deck))
    }
}

#[cfg(feature="wasm")]
#[wasm_bindgen]
impl AggregatedPublicKeys {
    #[wasm_bindgen(js_name="accumulate_shuffles")]
    pub fn accumulate_shuffles_wasm(self, deck: wasm::MaskedCards) -> AccumulateShuffles {
        AccumulateShuffles(self.0.accumulate_shuffles(deck.0))
    }
}

type AccInner = cards_protocol::shuffle::AccumulateShuffles<'static, Curve>;

#[derive(Clone,CanonicalSerialize)]
#[cfg_attr(feature="serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature="serde", serde(from = "CompressedChecked<Self>", into = "CompressedChecked<Self>"))]
#[repr(transparent)]
#[cfg_attr(feature="wasm", wasm_bindgen)]
pub struct AccumulateShuffles(pub(crate) AccInner);

impl core::ops::Deref for AccumulateShuffles {
    type Target = AccInner;
    fn deref(&self) -> &Self::Target { &self.0}
}
impl core::ops::DerefMut for AccumulateShuffles {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0}    
}
#[cfg(feature="serde")]
impl From<CompressedChecked<AccumulateShuffles>> for AccumulateShuffles {
    fn from(s: CompressedChecked<AccumulateShuffles>) -> Self { s.0 }
}
impl CanonicalDeserialize for AccumulateShuffles {
    fn deserialize_with_mode<R: ark_std::io::Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        Ok(AccumulateShuffles(AccInner::deserialize_with_mode(reader,compress,validate,PARAMS) ?))
    }
}
impl Valid for AccumulateShuffles {
    fn check(&self) -> Result<(), SerializationError> {
        self.0.check()
    }
}
impl AccumulateShuffles {
    #[cfg(feature="prover")]
    pub fn do_shuffle(
        &mut self, sk: &PlayerKeypair,
    ) -> CardResult<ShuffleMessage> {
        self.0.do_shuffle(&mut getrandom_or_panic(), sk)
    }

    pub fn apply_shuffle<'a>(&mut self, shuffle: &'a ShuffleMessage)
     -> CardResult<(&'a PlayerPublicKey,Option<usize>)>
    {
        Ok(self.0.apply_shuffle(shuffle)?)
    }
}

#[cfg_attr(feature="wasm", wasm_bindgen)]
impl AccumulateShuffles {
    pub fn is_completed(&self) -> bool { self.0.is_completed() }
    /// Always returns zero if more than 32 players
    pub fn remaining_mask(&self) -> u32 { self.0.remaining_mask() }
}

#[cfg(feature="wasm")]
#[wasm_bindgen]
impl AccumulateShuffles {
    #[cfg(feature="prover")]
    #[wasm_bindgen(js_name="do_shuffle")]
    pub fn do_shuffle_wasm(
        &mut self, sk: &PlayerKeypairWasm,
    ) -> wasm::ResultWasm<Vec<u8> /* ShuffleMessage */> {
        let shuffle = self.0.do_shuffle(&mut getrandom_or_panic(), &sk.0)?;
        Ok(shuffle.serialize_to_vec().unwrap())
    }

    #[wasm_bindgen(js_name="apply_shuffle")]
    pub fn apply_shuffle_wasm(&mut self, shuffle: &[u8]) -> wasm::ResultWasm<Option<usize>> {
        let shuffle = ShuffleMessage::deserialize_compressed(shuffle) ?;
        Ok(self.apply_shuffle(&shuffle)?.1)
    }

    #[wasm_bindgen(js_name="deserialize")]
    pub fn wasm_deserialize(selfy: &[u8]) -> wasm::ResultWasm<AccumulateShuffles> {
        Ok(AccumulateShuffles::deserialize_compressed(selfy) ?)
    }

    #[wasm_bindgen(js_name="serialize")]
    pub fn wasm_serialize(&self) -> Vec<u8> {
        self.serialize_to_vec().unwrap()
    }
}
