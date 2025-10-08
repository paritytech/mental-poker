use crate::{IntoTranscript};

use super::{Parameters, Statement, Witness, proof::Proof, NAME};


use ark_ec::{CurveGroup};
use ark_std::{borrow::BorrowMut, rand::{Rng, CryptoRng}};


use std::marker::PhantomData;

pub struct Prover<C: CurveGroup> {
    phantom: PhantomData<C>,
}

impl<C: CurveGroup> Prover<C> {
    pub fn create_proof<R: Rng+CryptoRng>(
        system_rng: &mut R,
        parameters: &Parameters<C>,
        statement: &Statement<C>,
        witness: &Witness<C>,
        t: impl IntoTranscript,
    ) -> Proof<C> {
        use ark_std::ops::Mul;

        let mut t = t.into_transcript();
        let t = t.borrow_mut();

        t.label(NAME);
        t.append(parameters.g);
        t.append(parameters.h);
        t.append(statement.0);
        t.append(statement.1);

        let omega: C::ScalarField = t.fork(b"rng").witness(system_rng).read_reduce();
        let a = parameters.g.mul(omega);
        let b = parameters.h.mul(omega);

        t.append(&a);
        t.append(&b);

        let c: C::ScalarField = t.challenge(b"ch").read_reduce();

        let r = omega + c * *witness;

        Proof { a, b, r }
    }
}


