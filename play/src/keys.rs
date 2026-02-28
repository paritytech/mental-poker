use cards_protocol::IntoTranscript;
use crate::*;

use ark_serialize::{CanonicalSerialize,CanonicalDeserialize,SerializationError,Compress,Validate,Valid,CompressedChecked};

#[cfg(feature="serde")]
use serde::{Serialize, Deserialize};

#[cfg(feature="wasm-bindgen")]
use wasm_bindgen::prelude::*;

pub fn generate_player(
    player_public_info: impl IntoTranscript,
) -> (PlayerHello, PlayerKeypair) {
    PARAMS.generate_player(&mut getrandom_or_panic(),player_public_info)
}

pub fn verify_player(
    pk: &PlayerHello,
    player_public_info: impl IntoTranscript,
) -> Result<(), CardProtocolError> {
    Ok(PARAMS.verify_player(pk,player_public_info)?)
}

type ApkInner = cards_protocol::keys::AggregatedPublicKeys<'static, Curve>;

#[derive(Clone,CanonicalSerialize,Debug)]
#[cfg_attr(feature="serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature="serde", serde(from = "CompressedChecked<Self>", into = "CompressedChecked<Self>"))]
#[repr(transparent)]
pub struct AggregatedPublicKeys(
    pub ApkInner
);

impl core::ops::Deref for AggregatedPublicKeys {
    type Target = ApkInner;
    fn deref(&self) -> &Self::Target { &self.0}
}

impl From<CompressedChecked<AggregatedPublicKeys>> for AggregatedPublicKeys {
    fn from(sig: CompressedChecked<AggregatedPublicKeys>) -> Self { sig.0 }
}
impl CanonicalDeserialize for AggregatedPublicKeys {
    fn deserialize_with_mode<R: ark_std::io::Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        Ok(AggregatedPublicKeys(ApkInner::deserialize_with_mode(reader,compress,validate,PARAMS) ?))
    }
}
impl Valid for AggregatedPublicKeys {
    fn check(&self) -> Result<(), SerializationError> {
        self.0.check()
    }
}

// fn verify_n_add
// fn verify_shuffle
// fn prove_merged_reveals

impl AggregatedPublicKeys {
    /// Shuffle cards and produce proof using system randomness
    ///
    /// Verified using `verify_shuffle`
    #[cfg_attr(feature="wasm-bindgen", wasm_bindgen(serde))]
    pub fn shuffle_and_remask_(
        &self, deck: &[MaskedCard],
    ) -> Result<ShuffleMessage, CardProtocolError> {
        self.shuffle_and_remask(&mut getrandom_or_panic(), deck)
    }
    
    pub fn verify_quit<'a,'b>(
        &mut self,
        reveals: &'a RevealsMerged,
        masked_cards: impl IntoIterator<Item=&'b MaskedCard>,
    ) -> Result<&'a [RevealToken], CardProtocolError> {  // Not CryptoError?
        let idx = self.0.player_index(&reveals.pk)?;
        verify_merged_reveals(reveals,masked_cards)
        .map(|r| { let _ = self.0.remove(idx); r })
    }
}

// Afaik prove_merged_reveals and verify_merged_reveals should
// opnly be called by Table, not directly.

pub fn prove_merged_reveals<'a>(
    key: &PlayerKeypair,
    masked_cards: impl IntoIterator<Item=&'a MaskedCard>,
) -> RevealsMerged {
    crate::PARAMS.prove_merged_reveals(&mut getrandom_or_panic(), key, masked_cards)
}

pub fn verify_merged_reveals<'a,'b>(
    reveals: &'a RevealsMerged,
    masked_cards: impl IntoIterator<Item=&'b MaskedCard>,
) -> Result<&'a [RevealToken], CardProtocolError> {  // Not CryptoError?
    Ok(crate::PARAMS.verify_merged_reveals(reveals, masked_cards)?)
}


//
// On AggregatedPublicKeys::
//

/*
#[cfg(feature = "bytes")]
pub mod bytes {
    pub fn generate_player(
        player_public_info: impl IntoTranscript,
    ) -> (PlayerHello, PlayerKeypair) {
        super::generate_player
    }
}
*/
