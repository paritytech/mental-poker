
use crate::{
    Scalar, MaskedCard,
    masking::Mask,
    keys::*,
};

use ark_ec::CurveGroup;
use ark_ff::{Field,One,Zero}; 
#[cfg(feature="prover")]
use ark_std::{rand::{Rng,CryptoRng}};

use cards_proofs::{
    error::CryptoError,
    homomorphic_encryption::{el_gamal::{self, ElGamal}, HomomorphicEncryptionScheme},
    zkp::{
        proofs::chaum_pedersen_dl_equality,
        ArgumentOfKnowledge,
    },
};

const REMASKING_RNG_SEED: &'static [u8] = b"Remasking Proof";

pub type ZKProofRemasking<C> = chaum_pedersen_dl_equality::proof::Proof<C>;

pub trait Remask<Scalar: Field, Enc: HomomorphicEncryptionScheme<Scalar>> {
    fn remask_card(
        &self,
        pp: &Enc::Parameters,
        shared_key: &Enc::PublicKey,
        r: &Scalar,
    ) -> Enc::Ciphertext;
}

impl<C: CurveGroup> Remask<C::ScalarField, ElGamal<C>> for MaskedCard<C> {
    fn remask_card(
        &self,
        pp: &el_gamal::Parameters<C>,
        shared_key: &AggregatePublicKey<C>,
        alpha: &C::ScalarField,
    ) -> el_gamal::Ciphertext<C> {
        let zero = el_gamal::Plaintext::zero();
        let masking_point = zero.mask_card(pp, shared_key, alpha);
        *self + masking_point
    }
}

impl<C: CurveGroup> crate::Parameters<C> {
    #[cfg(feature="prover")]
    pub fn prove_remask<R: Rng+CryptoRng>(
        &self,
        rng: &mut R,
        shared_key: &AggregatePublicKey<C>,
        original_card: &MaskedCard<C>,
        alpha: &Scalar<C>,
    ) -> (MaskedCard<C>, ZKProofRemasking<C>) {
        let remasked = original_card.remask_card(&self.enc_parameters, shared_key, alpha);

        // Map to Chaum-Pedersen parameters
        let cp_parameters =
            chaum_pedersen_dl_equality::Parameters::new(&self.enc_parameters.generator, shared_key);

        // Map to Chaum-Pedersen statement
        let minus_one = -Scalar::<C>::one();
        let negative_original = *original_card * minus_one;
        let statement_cipher = remasked + negative_original;
        let cp_statement =
            chaum_pedersen_dl_equality::Statement::new(&statement_cipher.0, &statement_cipher.1);

        let proof = chaum_pedersen_dl_equality::DLEquality::prove(
            rng,
            &cp_parameters,
            &cp_statement,
            alpha,
            REMASKING_RNG_SEED,
        ).expect("Infalible");

        (remasked, proof)
    }

    pub fn verify_remask(
        &self,
        shared_key: &AggregatePublicKey<C>,
        original_masked: &MaskedCard<C>,
        remasked: &MaskedCard<C>,
        proof: &ZKProofRemasking<C>,
    ) -> Result<(), CryptoError> {
        // Map to Chaum-Pedersen parameters
        let cp_parameters =
            chaum_pedersen_dl_equality::Parameters::new(&self.enc_parameters.generator, shared_key);

        // Map to Chaum-Pedersen statement
        let minus_one = -Scalar::<C>::one();
        let negative_original = *original_masked * minus_one;
        let statement_cipher = *remasked + negative_original;
        let cp_statement =
            chaum_pedersen_dl_equality::Statement::new(&statement_cipher.0, &statement_cipher.1);

        chaum_pedersen_dl_equality::DLEquality::verify(
            &cp_parameters,
            &cp_statement,
            proof,
            REMASKING_RNG_SEED,
        )
    }
}
