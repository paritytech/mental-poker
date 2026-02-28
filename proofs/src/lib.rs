#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

pub mod error;
pub mod homomorphic_encryption;
pub mod utils;
pub mod vector_commitment;
pub mod zkp;

pub use ark_transcript::{self as transcript, Transcript, IntoTranscript};
