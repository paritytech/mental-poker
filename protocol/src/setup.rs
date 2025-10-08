
use ark_ec::{CurveGroup}; // AffineRepr
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt, vec::Vec, rand::Rng,};

#[cfg(feature = "std")]
use std::io::{self, Write};

use cards_proofs::{
    // error::CryptoError;
    homomorphic_encryption::{el_gamal, HomomorphicEncryptionScheme},
    vector_commitment::{pedersen, HomomorphicCommitmentScheme},
};

#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Parameters<C: CurveGroup> {
    pub enc_parameters: el_gamal::Parameters<C>,
    pub commit_parameters: pedersen::CommitKey<C>,
    pub generator: el_gamal::Generator<C>,
}

/// Returns first the largest integer divisor below the square root,
/// as well as the quotient of k by this integer.
pub const fn mid_factor(k: usize) -> (usize,usize,usize) {
    // if k == 52 { return (2,26,0); } // Not much improvement over (4,13,0)
    let mut p = k;
    let mut j = 1;
    while {
        let mut i = 2;
        while i*i <= p {
            if p % i == 0 {
                j = i;
            }
            i += 1;
        }
        j == 1
    } { p += 1; }
    (j, p/j, p-k)
}

impl<C: CurveGroup> Parameters<C> {
    pub fn setup<R: Rng>(
        deterministic_rng: &mut R,
        size: usize,
    ) -> Parameters<C> {
        let enc_parameters = el_gamal::ElGamal::<C>::setup(deterministic_rng);
        // Importantly we only need n here for a single shuffle,
        // but our eviction protocol shuffles a smaller deck, so 
        // the quotient of the integer divisor could increase.
        // In particular 52 = 4 * 13, but if 5 cards were revealed
        // then we'd have 47, which is prime.
        // let (m,n,padding) = mid_factor(size);
        let commit_parameters = pedersen::PedersenCommitment::<C>::setup(deterministic_rng, size /* n */);
        let generator = el_gamal::ElGamal::<C>::generator(deterministic_rng);

        Parameters { enc_parameters, commit_parameters, generator }
    }

    pub fn parameters_size(&self) -> usize {
        self.commit_parameters.len()
    }

    pub fn check_deck_size(&self, size: usize) -> bool {
        let (_m,n,_padding) = mid_factor(size);
        n <= self.parameters_size()
    }

    #[cfg(feature = "std")]
    pub fn to_code<W: Write>(&self, w: &mut W, name: &str) -> io::Result<()> {
        use cards_proofs::utils::write_point;
        // let affine = affine.unwrap_or(std::any::type_name::<<C as CurveGroup>::Affine>());
        let projective = "Projective";
        let affine = "Affine";
        self.commit_parameters.to_code_first(w,affine)?;
        writeln!(w, "pub static {}: &'static Parameters<{}> = &Parameters {{", name, projective )?;
        // writeln!(w, "    m: {},",self.m)?;
        // writeln!(w, "    n: {},",self.n)?;

        write!(w, "    enc_parameters: cards_proofs::homomorphic_encryption::el_gamal::Parameters {{ generator: ")?;
        write_point(w, affine, &self.enc_parameters.generator)?;
        writeln!(w, "}},")?;

        write!(w, "    commit_parameters: ")?;
        self.commit_parameters.to_code_second(w, affine)?;

        write!(w, "    generator: cards_proofs::homomorphic_encryption::el_gamal::Plaintext(")?;
        write_point(w, affine, &self.generator.0)?;
        writeln!(w, "),")?;
        writeln!(w, "}};")
    }
}

impl<C: CurveGroup> fmt::Debug for Parameters<C> {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}