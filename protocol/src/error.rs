
use ark_std::{io};
use cards_proofs::error::*;
use thiserror::Error;

pub type ProtoResult<T> = ark_std::result::Result<T,CardProtocolError>;

/// This is an error that could occur when running a cryptographic primitive
#[derive(Error, Debug, PartialEq)]
pub enum CardProtocolError {
    /// Asked an `AggregatedPublicKeys` for a non-existant player.
    // Internal error type, aka developer miss-use.
    #[error("Player not present!")]
    PlayerNotPresent,
    // keys.rs (player_index), eviction.rs

    /// Reveal applied to the wrong card.
    // Internal error type, aka developer miss-use.
    #[error("Wrong card!")]
    WrongCard,
    // reveal.rs

    /// Returnned by `reveal::{card_position,reveal_position}`.
    ///
    /// `ZeroCard` should only occur after an eviction adds masked zero
    /// cards, so repeat the draw operation when `ZeroCard` occurs during
    /// a card draw operation.
    ///
    /// `ZeroCard` could occur earlier as some proof verification error
    /// whenever using those methods, meaning during eviction proofs.
    /// If so, this means cards were incorrectly masked, so probably
    /// missing shuffle rounds, but maybe missing deterministic masking.
    #[error("Unexpected zero card")]
    ZeroCard,
    // reveal.rs

    /// Returnned by `reveal::{card_position,reveal_position}`.
    ///
    /// Asked a deck for non-existant card's position
    // Internal error type, aka developer miss-use.
    #[error("Non-existant card")]
    UnrecognizedCard,
    // reveal.rs

    /// Eviction does not support duplicate cards in the game
    /// Redesign your deck creation or management.
    // Internal error type, aka developer miss-use
    #[error("Duplicate cards not allowed")]
    DuplicateCard,
    // eviction.rs only

    /// Internal error, perhaps in this crate.
    #[error("Duplicate player not allowed")]
    DuplicatePlayer,
    // eviction.rs only

    /// Indicates some broken game invariant, possibly caused by
    /// messages being mixed up between games, or by players doing
    /// something malicious.
    /// Internal error type, aka developer miss-use
    ///
    /// Examples: Aggregate public keys being wrong, decks being
    /// the wrong size, ...
    // TODO: Should this subsume some types above?  Or be split out?
    #[error("Wrong game: {0}")]
    WrongGame(&'static str),
    // eviction only

    /// ...
    #[error("{0}")]
    InvalidProof(&'static str),

    #[error("{0}")] // Previously the simplifying "Failed to verify proof", but why?   See https://docs.rs/thiserror/latest/thiserror/
    ProofError(#[from] CryptoError),

    // ark_std::io::Error is more efficent and infomrative than String, but lacks PartialEq
    // #[error("IoError in cards-proofs: {0}")]
    // IoError(ark_std::string::String),
    #[error("IoError in cards-protocol: {0:?}")]
    IoError(AlwayUnequal<ark_std::io::Error>),
}

impl From<io::Error> for CardProtocolError {
    fn from(err: io::Error) -> Self {
        // err.into::<CryptoError>().into()
        Self::IoError(AlwayUnequal(err))
    }
}

/*
impl CardProtocolError {
    pub(crate) fn player_not_present() -> CardProtocolError {
        ;
    }
}
*/
