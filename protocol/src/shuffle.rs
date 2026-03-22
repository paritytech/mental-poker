use super::{
    IntoTranscript,Transcript,
    Parameters, setup::mid_factor,
    error::CardResult,
    Scalar, keys::*,
    MaskedCard, remasking::Remask, 
};

use ark_ec::{AffineRepr,CurveGroup};
use ark_std::{borrow::{ToOwned}, io::{Read}, ops::Deref, vec::Vec, Zero, rand::{Rng,CryptoRng}, UniformRand};

use ark_serialize::{CanonicalSerialize,CanonicalDeserialize,SerializationError,Compress,Validate,Valid};

#[cfg(feature="serde")]
use ark_serialize::{CompressedChecked};

#[cfg(feature="serde")]
use serde::{Serialize, Deserialize};

use cards_proofs::{
    error::CryptoError,
    homomorphic_encryption::el_gamal,
    utils::permutation::Permutation,
    vector_commitment::{
        pedersen::PedersenCommitment,
        // HomomorphicCommitmentScheme,
    },
    zkp::{
        arguments::shuffle,
        ArgumentOfKnowledge,
    },
};


pub type ZKProofShuffle<C> = shuffle::proof::Proof<Scalar<C>, el_gamal::ElGamal<C>, PedersenCommitment<C>>;

/// Output and proof for a raw remask and shuffle operation,
/// but without any signature.
/// 
/// Anyone could perform a remask and shuffle operation.  We treat only
/// the permutation being applied, the masking factors, and the randomness
/// used in the proof as secret here. 
///
/// We do not require any secret keys in particular, so `ShuffleMessage`s
/// can/do not sign themselves.  All players must apply the remasks and
/// shuffles using hte same public key though, so you'll want some signed
/// wrapper for consensus and spam prevention.
#[derive(Clone,CanonicalSerialize,CanonicalDeserialize)]
#[cfg_attr(feature="serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature="serde", serde(from = "CompressedChecked<Self>", into = "CompressedChecked<Self>"))]
pub struct ShuffleUnsigned<C: CurveGroup> {
    pub deck: Vec<MaskedCard<C>>,     // Should come first for bytes interfaces
    pub proof: ZKProofShuffle<C>,
}

impl<C: CurveGroup> Deref for ShuffleUnsigned<C> {
    type Target = [MaskedCard<C>];
    fn deref(&self) -> &[MaskedCard<C>] { &self.deck }
}
#[cfg(feature="serde")]
impl<C: CurveGroup> From<CompressedChecked<ShuffleUnsigned<C>>> for ShuffleUnsigned<C> {
    fn from(s: CompressedChecked<ShuffleUnsigned<C>>) -> Self { s.0 }
}

fn pad_masked_cards<C: CurveGroup>(cards: &mut Vec<MaskedCard<C>>, padding: usize) {
    let zero_ct = el_gamal::Ciphertext(C::Affine::zero(),C::Affine::zero());
    for _ in 0..padding {
        cards.push(zero_ct);
    }
}

impl<C: CurveGroup> Parameters<C> {
    /// The mask-shuffle operation underlying mental poker.
    ///
    /// We suggest preparing cards using `zero_mask`, instead of kinda
    /// pointless the `mask` function.
    pub fn raw_shuffle_and_remask<R: Rng+CryptoRng>(
        &self,
        rng: &mut R,
        shared_key: &AggregatePublicKey<C>,
        deck: &[MaskedCard<C>],
        masking_factors: &[Scalar<C>],
        permutation: &Permutation,
        (m,n,padding): (usize,usize,usize),
        t: impl IntoTranscript,
    ) -> Result<ShuffleUnsigned<C>, CryptoError> {
        let size = permutation.len();

        // let start = ark_std::time::Instant::now();

        let permuted_deck = permutation.apply(&deck);
        let mut masked_shuffled = permuted_deck
            .iter()
            .zip(masking_factors)
            .map(|(masked_card, masking_factor)| {
                masked_card.remask_card(&self.enc_parameters, &shared_key, masking_factor)
            })
            .collect::<Vec<_>>();

        // println!("Masking {:?}",start.elapsed());

        let (mut deck, mut masking_factors, mut permutation) = (deck,masking_factors,permutation);
        let (padded_permutation, mut padded_masking_factors, mut padded_deck);
        if padding != 0 {
            let mut new_permutation: Vec<usize> = permutation.deref().to_owned();
            padded_masking_factors = masking_factors.to_owned();
            for _ in 0..padding {
                new_permutation.push( new_permutation.len() );
                padded_masking_factors.push(Zero::zero());
            }
            padded_permutation = new_permutation.into();
            permutation = &padded_permutation;
            masking_factors = &padded_masking_factors;
            padded_deck = deck.to_owned();
            pad_masked_cards(&mut padded_deck, padding);
            deck = &padded_deck;
            pad_masked_cards(&mut masked_shuffled, padding);
        };

        let shuffle_parameters = shuffle::Parameters::new(
            &self.enc_parameters,
            shared_key,
            &self.commit_parameters,
            &self.generator,
        );

        let shuffle_statement = shuffle::Statement::new(deck, &masked_shuffled, m, n);
        // Verifies the lengths all make sense, probably okay to unwrap
        // https://github.com/peer3to/mental-poker/blob/main/proofs/src/zkp/arguments/shuffle/mod.rs#L125
        shuffle_statement.is_valid()?;

        let witness = shuffle::Witness::new(permutation, masking_factors);

        let proof = shuffle::ShuffleArgument::prove(
            rng,
            &shuffle_parameters,
            &shuffle_statement,
            &witness,
            t,
        )?;
        // There are seven error sites that could trigger here.  Of these, three are
        // HomomorphicCommitmentScheme::commit which afaik merely requires enough SRS:
        // https://github.com/peer3to/mental-poker/blob/main/proofs/src/vector_commitment/pedersen/mod.rs#L83
        // The one reshape and two dot_product calls are length miss match errors:
        // https://github.com/peer3to/mental-poker/blob/main/proofs/src/utils/vector_arithmetic.rs
        // The remaining two origins are matrix_elements_product::Prover::prove and 
        // product_argument::prover::Prover::prove, which both contain more dot_product
        // and HomomorphicCommitmentScheme::commit calls, which all depend upon the length.
        // println!("Shuffle {:?}",start.elapsed());

        masked_shuffled.truncate(size);
        Ok(ShuffleUnsigned { deck: masked_shuffled, proof })
    }

    /// Verify the mask-shuffle operation by `shuffle_and_remask`.
    ///
    /// You never need thus unless you size the shuffle differently
    /// than `mid_factor` does, aka padding and reveals. 
    pub fn raw_verify_shuffle<'a>(
        &self,
        shared_key: &AggregatePublicKey<C>,
        original_deck: &[MaskedCard<C>],
        shuffled: &'a ShuffleUnsigned<C>,
        (m,n,padding): (usize,usize,usize),
        t: impl IntoTranscript,
    ) -> Result<&'a [MaskedCard<C>], CryptoError> {
        let mut original_deck = original_deck;
        let (mut padded_shuffled_deck, mut padded_original_deck);
        let shuffled_deck = if padding != 0 {
            padded_original_deck = original_deck.to_owned();
            pad_masked_cards(&mut padded_original_deck, padding);
            original_deck = &padded_original_deck;
            padded_shuffled_deck = shuffled.deck.to_owned();
            pad_masked_cards(&mut padded_shuffled_deck, padding);
            &padded_shuffled_deck
        } else { &shuffled.deck };

        let shuffle_parameters = shuffle::Parameters::new(
            &self.enc_parameters,
            shared_key,
            &self.commit_parameters,
            &self.generator,
        );

        let shuffle_statement = shuffle::Statement::new(original_deck, shuffled_deck, m, n);

        shuffle::ShuffleArgument::verify(
            &shuffle_parameters,
            &shuffle_statement,
            &shuffled.proof,
            t,
        )?;
        Ok(&shuffled.deck)
    }

}


/// Signed output and proof for a remask and shuffle operation,
/// 
/// We do not require the signing key have any relationship to the
/// `AggregatedPublicKeys`, but you would usually enforce that
/// each of the public keys in the `AggregatedPublicKeys` shuffles.
#[derive(Clone,CanonicalSerialize,CanonicalDeserialize)]
#[cfg_attr(feature="serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature="serde", serde(from = "CompressedChecked<Self>", into = "CompressedChecked<Self>"))]
pub struct ShuffleMessage<C: CurveGroup> {
    pub shuffle: ShuffleUnsigned<C>,     // Should come first for bytes interfaces
    pub pk: PlayerPublicKey<C>,
    pub sig: ZKProofKeyOwnership<C>,
}

impl<C: CurveGroup> Deref for ShuffleMessage<C> {
    type Target = [MaskedCard<C>];
    fn deref(&self) -> &[MaskedCard<C>] { self.deck() }
}
#[cfg(feature="serde")]
impl<C: CurveGroup> From<CompressedChecked<ShuffleMessage<C>>> for ShuffleMessage<C> {
    fn from(s: CompressedChecked<ShuffleMessage<C>>) -> Self { s.0 }
}

impl<C: CurveGroup> ShuffleMessage<C> {
    pub fn deck(&self) -> &[MaskedCard<C>] { &self.shuffle.deck }
}


const SHUFFLE_RNG_SEED: &'static [u8] = b"Shuffle Proof";

impl<'p,C: CurveGroup> AggregatedPublicKeys<'p,C> {
    pub fn shuffle_and_remask<R: Rng+CryptoRng>( // shuffle_and_remask
        &self,
        rng: &mut R,
        sk: &PlayerKeypair<C>,
        deck: &[MaskedCard<C>],
    ) -> CardResult<ShuffleMessage<C>> {
        let size = deck.len();
        let masking_factors: Vec<Scalar<C>> = (0..size).map(|_| UniformRand::rand(rng)).collect();
        let permutation = Permutation::from_rng(rng,size);
        let size = mid_factor(size);
        let mut t = Transcript::new_labeled(SHUFFLE_RNG_SEED);
        let shuffle = self.parameters().raw_shuffle_and_remask(
            rng, self.aggregate_key(), deck, &masking_factors, &permutation, size, &mut t,
        )?;
        let sig = self.parameters().prove_key_ownership(rng, sk, &mut t);
        Ok(ShuffleMessage { shuffle, pk: sk.pk.clone(), sig })
    }

    /// Verify the mask-shuffle operation by `shuffle_and_remask`.
    ///
    /// We return the public key with which the caller should determine
    /// if all or enough parties suffled yet.
    pub fn verify_shuffle<'a>(
        &self,
        original_deck: &[MaskedCard<C>],
        shuffled: &'a ShuffleMessage<C>,
    ) -> CardResult<(&'a PlayerPublicKey<C>,&'a [MaskedCard<C>])> {
        let ShuffleMessage { shuffle, pk, sig } = shuffled;
        let size = mid_factor(original_deck.len());
        let mut t = Transcript::new_labeled(SHUFFLE_RNG_SEED);
        let new_deck = self.parameters().raw_verify_shuffle(
            self.aggregate_key(), original_deck, shuffle, size, &mut t
        )?;
        self.parameters().verify_key_ownership(pk, &mut t, sig)?;
        Ok((pk,new_deck))
    }

    pub fn accumulate_shuffles(self, deck: Vec<MaskedCard<C>>) -> AccumulateShuffles<'p,C> {
        let l = self.players().len();
        let remaining_mask = if l <= 32 { (1u64 << l)-1 } else { 0 } as u32;
        let remaining_key = self.aggregate_key().into_group();
        AccumulateShuffles { apk: self, remaining_mask, remaining_key, deck, }
    }
}


#[derive(Clone,CanonicalSerialize)]
#[cfg_attr(feature="serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature="serde", serde(from = "CompressedChecked<Self>", into = "CompressedChecked<Self>"))]
pub struct AccumulateShuffles<'p,C: CurveGroup> {
    apk: AggregatedPublicKeys<'p,C>,
    remaining_mask: u32,
    remaining_key: C,
    deck: Vec<MaskedCard<C>>,
}

#[cfg(feature="serde")]
impl<C: CurveGroup> From<CompressedChecked<AccumulateShuffles<C>>> for AccumulateShuffles<C> {
    fn from(s: CompressedChecked<AccumulateShuffles<C>>) -> Self { s.0 }
}

impl<'p, C: CurveGroup> Valid for AccumulateShuffles<'p,C> {
    fn check(&self) -> Result<(), SerializationError> {
        self.apk.check()?;
        self.remaining_key.check()?;
        self.deck.check()
    }
}

impl<'p,C: CurveGroup> AccumulateShuffles<'p,C> {
    pub fn parameters(&self) -> &'p crate::Parameters<C> { self.apk.parameters() }
    pub fn apk(&self) -> &AggregatedPublicKeys<'p,C> { &self.apk }
    pub fn remaining_key(&self) -> &C { &self.remaining_key }
    pub fn deck(&self) -> &[MaskedCard<C>] { &self.deck }

    // Should this apply our own shuffle?
    pub fn do_shuffle<R: Rng+CryptoRng>( // shuffle_and_remask
        &mut self,
        rng: &mut R,
        sk: &PlayerKeypair<C>,
    ) -> CardResult<ShuffleMessage<C>> {
        self.apk.shuffle_and_remask(rng, sk, self.deck.as_slice())
    }

    /// Apply the shuffle
    ///
    /// Always applies valid shuffles, even if not by a participant,
    /// so if you must enforce the origin then check `shuffle.pk`
    /// before invoking this.
    pub fn apply_shuffle<'a>(
        &mut self, shuffle: &'a ShuffleMessage<C>
    ) -> CardResult<(&'a PlayerPublicKey<C>,Option<usize>)>
    {
        let (pk,deck) = self.apk.verify_shuffle(&self.deck, shuffle)?;
        self.deck.clear();
        self.deck.extend_from_slice(deck);
        let i = self.apk.player_index(&shuffle.pk).ok();
        if i.is_some()  {
            self.remaining_mask &= !(1u32 << i.unwrap());
            self.remaining_key = self.remaining_key - pk;
        }
        Ok((pk,i))
    }

    /// Always returns zero if more than 32 players
    pub fn remaining_mask(&self) -> u32 { self.remaining_mask }

    pub fn is_completed(&self) -> bool { self.remaining_key.is_zero() }

    /// If successful, this leaves `self` unusable.
    pub fn completed(&mut self) -> Option<(AggregatedPublicKeys<'p,C>,Vec<MaskedCard<C>>)> {
        if !self.is_completed() { return None; }
        let mut apk = self.apk.parameters().create_aggregate_keys();
        core::mem::swap(&mut apk, &mut self.apk);
        let deck = core::mem::replace(&mut self.deck, Vec::new());
        Some((apk,deck))
    }

    /// Deserialize `AccumulateShuffles` without checking anything.
    pub fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
        parameters: &'p Parameters<C>,
    ) -> Result<AccumulateShuffles<'p,C>,SerializationError> {
        Ok(AccumulateShuffles {
            apk: AggregatedPublicKeys::deserialize_with_mode(&mut reader,compress,validate,parameters)?,
            remaining_mask: CanonicalDeserialize::deserialize_with_mode(&mut reader,compress,validate)?,
            remaining_key: CanonicalDeserialize::deserialize_with_mode(&mut reader,compress,validate)?,
            deck: CanonicalDeserialize::deserialize_with_mode(&mut reader,compress,validate)?,
        })
    }

    /// Deserialize `AggregatedPublicKeys` from a serialized `Vec<PlayerPublicKey<C>>`.   // without checking anything.
    pub fn deserialize_compressed<R: Read>(r: R, parameters: &'p Parameters<C>) -> Result<AccumulateShuffles<'p,C>,SerializationError> {
        Self::deserialize_with_mode(r,Compress::Yes,Validate::Yes,parameters)
    }
}
