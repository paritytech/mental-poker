pub mod proof;
pub mod prover;

#[cfg(test)]
mod test;

const NAME: &'static [u8] = b"Chaum-Pedersen";
const ERROR: &'static str = "Chaum-Pedersen";

use crate::{IntoTranscript, error::*};
use crate::zkp::ArgumentOfKnowledge;
use ark_ec::{CurveGroup,PrimeGroup};
use ark_std::{marker::PhantomData, rand::{Rng, CryptoRng}};


pub struct DLEquality<'a, C: CurveGroup> {
    _group: PhantomData<&'a C>,
}

#[derive(Copy, Clone)]
pub struct Parameters<'a, C: CurveGroup> {
    pub g: &'a C::Affine,
    pub h: &'a C::Affine,
}

impl<'a, C: CurveGroup> Parameters<'a, C> {
    pub fn new(g: &'a C::Affine, h: &'a C::Affine) -> Self {
        Self { g, h }
    }
}

/// Statement for a Chaum-Pedersen proof of discrete logarithm equality.
/// Expects two points $A$ and $B$ such that for some secret $x$ and parameters
/// $G$ and $H$, $A = xG$ and $B=xH$
#[derive(Copy, Clone)]
pub struct Statement<'a, C: CurveGroup>(pub &'a C::Affine, pub &'a C::Affine);

impl<'a, C: CurveGroup> Statement<'a, C> {
    pub fn new(point_a: &'a C::Affine, point_b: &'a C::Affine) -> Self {
        Self(point_a, point_b)
    }
}

type Witness<C> = <C as PrimeGroup>::ScalarField;

impl<'a, C: CurveGroup> ArgumentOfKnowledge for DLEquality<'a, C> {
    type CommonReferenceString = Parameters<'a, C>;
    type Statement = Statement<'a, C>;
    type Witness = Witness<C>;
    type Proof = proof::Proof<C>;

    fn prove<R: Rng+CryptoRng>(
        rng: &mut R,
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        witness: &Self::Witness,
        t: impl IntoTranscript,
    ) -> CryptoResult<Self::Proof> {
        Ok(prover::Prover::create_proof(rng, common_reference_string, statement, witness, t))
    }

    fn verify(
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        proof: &Self::Proof,
        t: impl IntoTranscript,
    ) -> CryptoResult<()> {
        proof.verify(common_reference_string, statement, t)
    }
}
