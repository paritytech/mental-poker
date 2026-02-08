// use wasm_bindgen::prelude::*;

pub mod serialize;
pub use serialize::{MyDeserialize, MySerialize};

pub use cards_protocol::error::CardProtocolError;

mod keys;
pub use keys::AggregatedPublicKeysExt;

#[cfg(test)]
pub mod more;

// arkworks

pub type Scalar = ark_secp256k1::Fr;
pub type Curve = ark_secp256k1::Projective;
pub type Affine = ark_secp256k1::Affine;

// deck

pub use deck_secp256k1::{DECK, PARAMS};

// cards_protocol

pub type MaskedCard = cards_protocol::MaskedCard<Curve>;
pub type UnmaskedCard = cards_protocol::UnmaskedCard<Curve>;

// cards_protocol::setup

pub type Parameters = cards_protocol::setup::Parameters<Curve>;

// cards_protocol::keys

pub type PlayerKeypair = cards_protocol::keys::PlayerKeypair<Curve>;
pub type PlayerHello = cards_protocol::keys::PlayerHello<Curve>;
pub type AggregatedPublicKeys = cards_protocol::keys::AggregatedPublicKeys<'static, Curve>;

// cards_protocol::reveal

pub type RevealMessage = cards_protocol::reveal::RevealMessage<Curve>;
pub type RevealsMerged = cards_protocol::reveal::RevealsMerged<Curve>;
pub type AccumulateReveals = cards_protocol::reveal::AccumulateReveals<'static, Curve>;

// cards_protocol::shuffle

pub type ShuffleMessage = cards_protocol::shuffle::ShuffleMessage<Curve>;


/*
#[wasm_bindgen]
pub fn main() -> anyhow::Result<(),JsValue> {
}
*/
