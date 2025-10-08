
use crate::{
    CanonicalSerialize,CanonicalDeserialize,
    IntoTranscript,Transcript,
    Scalar, UnmaskedCard, MaskedCard,
    keys::*,
};

use ark_ec::{AffineRepr,CurveGroup};
use ark_ff::{Field,One,Zero};
use ark_std::{borrow::BorrowMut, ops::Mul, vec::Vec, rand::{Rng,CryptoRng}};

use cards_proofs::{
    error::CryptoError,
    homomorphic_encryption::{el_gamal::{self, ElGamal}, HomomorphicEncryptionScheme},
    zkp::{
        proofs::chaum_pedersen_dl_equality,
        ArgumentOfKnowledge,
    },
};


/// Create a `MaskedCard` from an `UnmaskedCard` without doing any masking.
pub fn zero_mask<C: CurveGroup>(card: &UnmaskedCard<C>) ->  MaskedCard<C> {
    el_gamal::Ciphertext(C::Affine::zero(),card.0)
}

/// Create a `Vec<MaskedCard>` from `UnmaskedCard`s without doing any masking.
pub fn zero_mask_cards<'a,C: CurveGroup>(cards: impl IntoIterator<Item=&'a UnmaskedCard<C>>) -> Vec<MaskedCard<C>> {
    cards.into_iter().map(zero_mask).collect()
}

/// Create a `Vec<MaskedCard>` from `UnmaskedCard`s without doing any masking.
pub fn zero_mask_affines<'a,C: CurveGroup>(cards: impl IntoIterator<Item=&'a <C as CurveGroup>::Affine>) -> Vec<MaskedCard<C>> {
    cards.into_iter().map(|p| zero_mask(&el_gamal::Plaintext(*p))).collect()
}


pub trait Mask<Scalar: Field, Enc: HomomorphicEncryptionScheme<Scalar>> {
    fn mask_card(
        &self,
        pp: &Enc::Parameters,
        shared_key: &Enc::PublicKey,
        r: &Scalar,
    ) -> Enc::Ciphertext;
}

impl<C: CurveGroup> Mask<C::ScalarField, ElGamal<C>> for UnmaskedCard<C> {
    fn mask_card(
        &self,
        pp: &el_gamal::Parameters<C>,
        shared_key: &el_gamal::PublicKey<C>,
        r: &C::ScalarField,
    ) -> el_gamal::Ciphertext<C> {
        ElGamal::<C>::encrypt(pp, shared_key, self, r)
    }
}

const MASKING_RNG_SEED: &'static [u8] = b"Masking Proof";

pub type ZKProofMasking<C> = chaum_pedersen_dl_equality::proof::Proof<C>;

fn el_gammal_mask<C: CurveGroup>(
    pp: &el_gamal::Parameters<C>, // enc_parameters
    shared_key: &el_gamal::PublicKey<C>, 
    alpha: &C::ScalarField
) ->  MaskedCard<C> {
    let nonce = pp.generator.mul(alpha).into_affine();
    let cipher = shared_key.mul(alpha).into_affine();
    let mp = el_gamal::Ciphertext::<C>(nonce,cipher);
    debug_assert_eq!(mp,el_gamal::Plaintext::<C>::zero().mask_card(pp, shared_key, alpha));
    mp
}

impl<C: CurveGroup> crate::Parameters<C> {
    pub fn mask_from_key(
        &self,
        shared_key: &el_gamal::PublicKey<C>, 
        r: &C::ScalarField,
    ) ->  MaskedCard<C> {
        el_gammal_mask(&self.enc_parameters,shared_key,r)
    }

    /// Mask card using our aggregate public key
    pub fn mask_card(
        &self,
        plaintext: &el_gamal::Plaintext<C>,
        shared_key: &el_gamal::PublicKey<C>, 
        r: &Scalar<C>,
    ) -> el_gamal::Ciphertext<C> {
        plaintext.mask_card(
            &self.enc_parameters,
            shared_key,
            r
        )
    }

    /// Create a `MaskedCard` from an explicitly specified `UnmaskedCard`.
    ///
    /// It's unclear if the following is correct right now, maybe the
    /// shuffle even depends upon not knowing the mask, shich would
    /// create a mess in eviction.
    ///
    /// It's unclear how this would ever be usedful when representing some
    /// conventional physical card game, but it maybe becomes useful for
    /// cryptographic card games not representable by physical cards.
    pub fn prove_mask<R: Rng+CryptoRng>(
        &self,
        rng: &mut R,
        shared_key: &AggregatePublicKey<C>,
        original_card: &UnmaskedCard<C>,
        r: &Scalar<C>,
    ) -> (MaskedCard<C>, ZKProofMasking<C>) {
        let masked_card = original_card.mask_card(&self.enc_parameters, shared_key, r);
        let g = self.enc_parameters.generator;

        // Map to Chaum-Pedersen parameters
        let cp_parameters = chaum_pedersen_dl_equality::Parameters::new(&g, shared_key);

        // Map to Chaum-Pedersen statement
        let minus_one = -Scalar::<C>::one();
        let negative_original = original_card.0.mul(minus_one).into_affine();
        let statement_cipher = (masked_card.1 + negative_original).into_affine();
        let cp_statement =
            chaum_pedersen_dl_equality::Statement::<C>::new(&masked_card.0, &statement_cipher);

        let proof = chaum_pedersen_dl_equality::DLEquality::prove(
            rng,
            &cp_parameters,
            &cp_statement,
            r,
            MASKING_RNG_SEED,
        ).expect("Infalible");

        (masked_card, proof)
    }

    pub fn verify_mask(
        &self,
        shared_key: &AggregatePublicKey<C>,
        card: &UnmaskedCard<C>,
        masked_card: &MaskedCard<C>,
        proof: &ZKProofMasking<C>,
    ) -> Result<(), CryptoError> {
        // Map to Chaum-Pedersen parameters
        let cp_parameters =
            chaum_pedersen_dl_equality::Parameters::new(&self.enc_parameters.generator, shared_key);

        // Map to Chaum-Pedersen statement
        let minus_one = -Scalar::<C>::one();
        let negative_original = card.0.mul(minus_one).into_affine();
        let statement_cipher = (masked_card.1 + negative_original).into_affine();
        let cp_statement =
            chaum_pedersen_dl_equality::Statement::<C>::new(&masked_card.0, &statement_cipher);

        chaum_pedersen_dl_equality::DLEquality::verify(
            &cp_parameters,
            &cp_statement,
            proof,
            MASKING_RNG_SEED,
        )
    }

    pub fn deterministic_masking(
        &self,
        mut t: Transcript,
    ) -> impl Fn(&el_gamal::Plaintext<C>) -> Scalar<C> {
        t.label(b"deterministic_mask");
        move |plaintext: &el_gamal::Plaintext<C>| -> Scalar<C> {
            let mut t = t.clone();
            t.append(plaintext);
            t.challenge(b"mask").read_reduce()
        }
    }
}

#[derive(Clone,CanonicalSerialize,CanonicalDeserialize)] // Debug
pub struct MaskingBatch<C: CurveGroup> {
    pub masked_cards: Vec<MaskedCard<C>>,
    pub masking_proofs: Vec<ZKProofMasking<C>>,
}

impl<'p,C: CurveGroup> crate::keys::AggregatedPublicKeys<'p,C> {
    pub fn prove_masks<'a,R: Rng+CryptoRng>(
        &self,
        rng: &mut R,
        cards: impl IntoIterator<Item=UnmaskedCard<C>>,
        rs: impl IntoIterator<Item=&'a Scalar<C>>, //Option<_> ??
    ) -> MaskingBatch<C> {
        let (masked_cards, masking_proofs) = cards.into_iter().zip(rs)
        .map(|(oc,r)| self.parameters().prove_mask(rng, self.aggregate_key(), &oc, r))
        .unzip();
        MaskingBatch { masked_cards, masking_proofs, }
    }

    pub fn verify_masks<'a>(
        &self,
        cards: impl IntoIterator<Item=UnmaskedCard<C>>,
        masked: &MaskingBatch<C>,
    ) -> Result<(), CryptoError> {
        let MaskingBatch { masked_cards, masking_proofs } = masked;
        for (i,oc) in cards.into_iter().enumerate() {
            self.parameters().verify_mask(
                self.aggregate_key(), &oc, &masked_cards[i], &masking_proofs[i]
            )?;
        }
        Ok(())
    }

    /// Initial deterministic masking fuctions
    ///
    /// Assumes no repeated cards.
    pub fn deterministic_masking(
        &self,
        mut t: Transcript,
    ) -> impl Fn(&el_gamal::Plaintext<C>) -> Scalar<C> {
        t.label(b"apk");
        self.append(&mut t);
        self.parameters().deterministic_masking(t)
    }

    /// Mask card using our aggregate public key
    pub fn mask_card(
        &self,
        plaintext: &el_gamal::Plaintext<C>,
        r: &Scalar<C>,
    ) -> el_gamal::Ciphertext<C> {
        self.parameters().mask_card(plaintext,self.aggregate_key(),r)
    }

    /// Initial deterministic mask, but `zero_mask` suffices before shuffles.
    pub fn deterministically_masked_card(
        &self,
        plaintext: &el_gamal::Plaintext<C>,
        t: impl IntoTranscript,
    ) -> el_gamal::Ciphertext<C> {
        let t = t.into_transcript().borrow_mut().clone();
        self.mask_card(plaintext,&self.deterministic_masking(t)(plaintext))
    }

    /// Create a `Vec<MaskedCard>` from `UnmaskedCard`s without doing any masking.
    pub fn deterministically_masked<'a>(
        &self,
        cards: impl IntoIterator<Item=&'a UnmaskedCard<C>>,
        t: impl IntoTranscript,
    ) -> Vec<MaskedCard<C>> {
        let t = t.into_transcript().borrow_mut().clone();
        let mask = self.deterministic_masking(t);
        cards.into_iter().map(|pt| self.mask_card(pt,&mask(pt))).collect()
    }
}



