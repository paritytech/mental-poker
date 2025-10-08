#![no_std]

#[cfg(feature = "std")]
extern crate std; // #[macro_use]

use cards_deck::SortedDeck;
use cards_proofs::homomorphic_encryption::el_gamal::Plaintext;


mod deck_secp256k1;

pub const DECK_SECP256K1: &'static SortedDeck<ark_secp256k1::Affine> =
    SortedDeck::from_slice(deck_secp256k1::DECK_SECP256K1);


pub const DECK: &'static [Plaintext<ark_secp256k1::Projective>] =
    cards_deck::cast_deck(deck_secp256k1::DECK_SECP256K1);

// Comment out this line briefly when changing deck size.  Latex style!
pub use deck_secp256k1::PARAMS_SECP256K1 as PARAMS;


#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "std")]
    fn write_header<W: std::io::Write>(w: &mut W) -> std::io::Result<()> {
        writeln!(w, "// @generated")?;
        writeln!(w, "use ark_ff::MontFp;")?;
        writeln!(w, "use cards_proofs::utils::cow::CowVec;")?;
        writeln!(w, "use cards_protocol::Parameters;")?;
        writeln!(w, "")?;
        writeln!(w, "type Affine = ark_secp256k1::Affine;")?;
        writeln!(w, "type Projective = ark_secp256k1::Projective;")?;
        writeln!(w, "")
    }

    #[cfg(feature = "std")]
    fn open_fresh(filename: &str) -> std::fs::File {
        let mut path: std::path::PathBuf = "fresh".into();
        let _ = std::fs::create_dir(path.clone());
        path.push(filename);
        let mut w = std::fs::File::create(path).expect("File open prevented!");
        write_header(&mut w).expect("Write failed");
        w
    }

    #[cfg(feature = "std")]
    #[test]
    fn deck_secp256k1() {
        let mut rng = ark_transcript::Transcript::new_labeled(b"Peer3 secp256k1 card deck")
            .challenge(b"200 cards");
        let deck = SortedDeck::<ark_secp256k1::Affine>::from_rng(200, &mut rng);

        let mut w = open_fresh("deck_secp256k1.rs");
        deck.to_code(&mut w, "DECK_SECP256K1").expect("Write failed");

        assert_eq!(deck.0, crate::DECK_SECP256K1.0);

        // #[cfg(feature = "cards-protocol")] { .. }
        cards_protocol::Parameters::<ark_secp256k1::Projective>::setup(&mut rng, 200)
            .to_code(&mut w, "PARAMS_SECP256K1")
            .expect("Write failed");
    }
}
