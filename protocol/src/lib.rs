#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

// #[cfg(not(feature = "std"))]
// #[macro_use]
// extern crate alloc;


pub use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};

pub use ark_transcript::{self as transcript, Transcript, IntoTranscript};

use cards_proofs::{
    // error::CryptoError as CardProtocolError,
    homomorphic_encryption::el_gamal,
};



pub mod error;

pub mod setup;
pub use setup::{Parameters};

pub mod keys;
pub use keys::{PlayerHello, PlayerKeypair};

pub mod deck;

pub mod masking;

pub mod remasking;

pub mod reveal;
pub use reveal::{RevealToken, RevealMessage};

pub mod shuffle;

#[cfg(test)]
mod tests;


pub type Scalar<C> = <C as PrimeGroup>::ScalarField;

pub type AffinePoint<C> = <C as CurveGroup>::Affine;

/// An open playing card. In this Discrete Log-based implementation of the Barnett-Smart card protocol
/// a card is an el-Gamal plaintext. We create a type alias to implement the `Mask` trait on it.
pub type UnmaskedCard<C> = el_gamal::Plaintext<C>;

/// A masked (flipped) playing card. Note that a player masking a card will know the mapping from
/// open to masked card. All other players must remask to guarantee that the card is privately masked.
/// We create a type alias to implement the `Mask` trait on it.
pub type MaskedCard<C> = el_gamal::Ciphertext<C>;


