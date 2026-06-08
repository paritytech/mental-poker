use cards_protocol::IntoTranscript;
use crate::*;

use ark_serialize::{CanonicalSerialize,CanonicalDeserialize,SerializationError,Compress,Validate,Valid};
#[cfg(feature="serde")]
use ark_serialize::{CompressedChecked};
#[cfg(feature="serde")]
use serde::{Serialize, Deserialize};

// #[cfg(feature="wasm")]
// use wasm_bindgen::prelude::*;


pub fn player_keygen() -> PlayerKeypair {
    PARAMS.player_keygen(&mut getrandom_or_panic())
}

pub fn player_deserialize(selfy: &[u8]) -> Result<PlayerKeypair,SerializationError> {
    PARAMS.deserialize_player(selfy)
}

/// Include any delegating public key in `player_public_info` for back certification
pub fn prove_player(
    key: &PlayerKeypair,
    player_public_info: impl IntoTranscript,
) -> PlayerHello {
    PARAMS.prove_player(&mut getrandom_or_panic(),key,player_public_info)
}

/// Include any delegating public key in `player_public_info` for back certification
// We cannot return a Vec<u8> plus another typeunder wasm-bindgen ?!?
pub fn generate_player(
    player_public_info: impl IntoTranscript,
) -> (PlayerHello, PlayerKeypair) {
    PARAMS.generate_player(&mut getrandom_or_panic(),player_public_info)
}

pub fn verify_player(
    pk: &PlayerHello,
    player_public_info: impl IntoTranscript,
) -> CardResult<&PlayerPublicKey> {
    Ok(PARAMS.verify_player(pk,player_public_info)?)
}


type ApkInner = cards_protocol::keys::AggregatedPublicKeys<'static, Curve>;

#[derive(Clone,CanonicalSerialize,Debug)]
#[cfg_attr(feature="serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature="serde", serde(from = "CompressedChecked<Self>", into = "CompressedChecked<Self>"))]
#[repr(transparent)]
#[cfg_attr(feature="wasm", wasm_bindgen)]
pub struct AggregatedPublicKeys(
    pub(crate) ApkInner
);

impl core::ops::Deref for AggregatedPublicKeys {
    type Target = ApkInner;
    fn deref(&self) -> &Self::Target { &self.0}
}
impl core::ops::DerefMut for AggregatedPublicKeys {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0}    
}
#[cfg(feature="serde")]
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

/// Build AggregatedPublicKeys from a list of (hello_bytes, name_bytes) pairs.
/// Verifies each player's hello and adds their key to the aggregation.
pub fn build_aggregate_keys(
    players: &[(&[u8], &[u8])], // (hello_bytes, name_bytes)
) -> CardResult<AggregatedPublicKeys> {
    use ez_serialize::EzDeserialize;
    let mut apk = AggregatedPublicKeys(PARAMS.create_aggregate_keys());
    for (hello_bytes, name_bytes) in players {
        let hello = PlayerHello::deserialize(*hello_bytes)
            .map_err(|_| CardProtocolError::PlayerNotPresent)?;
        apk.0.verify_n_add(hello, *name_bytes)?;
    }
    Ok(apk)
}

impl AggregatedPublicKeys {
    pub fn verify_quit(
        &mut self,
        reveals: &RevealsMerged,
        masked_cards: &mut [MaskedCard],
    ) -> CardResult<()> {  // Not CryptoError?
        let idx = self.0.player_index(&reveals.pk)?;
        for (rt,mc) in verify_merged_reveals(reveals,masked_cards.iter())?.iter().zip(masked_cards.iter_mut()) {
            cards_protocol::reveal::update_masked_card(mc,rt);
        }
        let _ = self.0.remove(idx);
        Ok(())
    }
}

// We would not typically call prove_merged_reveals and verify_merged_reveals directly.

pub fn prove_merged_reveals<'a>(
    key: &PlayerKeypair,
    masked_cards: impl IntoIterator<Item=&'a MaskedCard>,
) -> RevealsMerged {
    crate::PARAMS.prove_merged_reveals(&mut getrandom_or_panic(), key, masked_cards)
}

pub fn verify_merged_reveals<'a,'b>(
    reveals: &'a RevealsMerged,
    masked_cards: impl IntoIterator<Item=&'b MaskedCard>,
) -> CardResult<&'a [RevealToken]> {  // Not CryptoError?
    Ok(crate::PARAMS.verify_merged_reveals(reveals, masked_cards)?)
}
