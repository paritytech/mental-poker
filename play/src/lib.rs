
use getrandom_or_panic::getrandom_or_panic;

#[cfg(feature="wasm")]
use wasm_bindgen::prelude::*;

pub use cards_protocol::error::CardProtocolError;
// pub use cards_proofs::error::CryptoError;

#[cfg(feature="wasm")]
pub mod wasm;

pub mod keys;
pub use keys::AggregatedPublicKeys;

#[cfg(feature="wasm")]
pub mod keys_wasm;
#[cfg(feature="wasm")]
pub use keys_wasm::PlayerKeypairWasm;

mod shuffle;
pub use shuffle::AccumulateShuffles;

mod reveals;
pub use reveals::AccumulateReveals;

#[cfg(test)]
pub mod more;

// arkworks

pub type Scalar = ark_secp256k1::Fr;
pub type Curve = ark_secp256k1::Projective;
pub type Affine = ark_secp256k1::Affine;

// deck

pub use deck_secp256k1::{DECK, PARAMS};

pub fn zero_mask_deck() -> Vec<MaskedCard> {
    cards_protocol::masking::zero_mask_cards(DECK)
}

// cards_protocol

pub type MaskedCard = cards_protocol::MaskedCard<Curve>;
pub type UnmaskedCard = cards_protocol::UnmaskedCard<Curve>;

// cards_protocol::setup

pub type Parameters = cards_protocol::setup::Parameters<Curve>;

// cards_protocol::keys

pub type PlayerKeypair = cards_protocol::keys::PlayerKeypair<Curve>;
pub type PlayerHello = cards_protocol::keys::PlayerHello<Curve>;
pub type PlayerPublicKey = cards_protocol::keys::PlayerPublicKey<Curve>;
// pub type AggregatedPublicKeys = cards_protocol::keys::AggregatedPublicKeys<'static, Curve>;

// cards_protocol::reveal

pub type RevealToken = cards_protocol::reveal::RevealToken<Curve>;
pub type RevealMessage = cards_protocol::reveal::RevealMessage<Curve>;
pub type RevealsMerged = cards_protocol::reveal::RevealsMerged<Curve>;
// pub type AccumulateReveals = cards_protocol::reveal::AccumulateReveals<'static, Curve>;

// cards_protocol::shuffle

pub type ShuffleMessage = cards_protocol::shuffle::ShuffleMessage<Curve>;

