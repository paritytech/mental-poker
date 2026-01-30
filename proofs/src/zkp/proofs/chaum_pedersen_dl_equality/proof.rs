use crate::{IntoTranscript, error::*};

use super::{Parameters, Statement, NAME, ERROR};

use ark_ec::{CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::BorrowMut, vec::Vec};

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize, Debug)]
pub struct Proof<C>
where
    C: CurveGroup,
{
    pub(crate) a: C::Affine,
    pub(crate) b: C::Affine,
    pub(crate) r: C::ScalarField,
}

impl<C: CurveGroup> Proof<C> {
    pub fn verify(
        &self,
        parameters: &Parameters<C>,
        statement: &Statement<C>,
        t: impl IntoTranscript,
    ) -> CryptoResult<()> {
        use ark_std::ops::Mul;

        let mut t = t.into_transcript();
        let t = t.borrow_mut();

        t.label(NAME);
        t.append(parameters.g);
        t.append(parameters.h);
        t.append(statement.0);
        t.append(statement.1);

        t.append(&self.a);
        t.append(&self.b);

        let c: C::ScalarField = t.challenge(b"ch").read_reduce();

        // g * r ==? a + x*c
        if parameters.g.mul(self.r) != self.a + statement.0.mul(c) {
            return Err(CryptoError::ProofVerificationError(ERROR.into()));
        }

        // h * r ==? b + y*c
        if parameters.h.mul(self.r) != self.b + statement.1.mul(c) {
            return Err(CryptoError::ProofVerificationError(ERROR.into()));
        }

        Ok(())
    }
}
