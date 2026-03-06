use super::{
    IntoTranscript,
    CanonicalSerialize,CanonicalDeserialize,
    Parameters, setup::mid_factor,
    error::CardProtocolError,
    Scalar, keys::*,
    MaskedCard, remasking::Remask, 
};

use ark_ec::{AffineRepr,CurveGroup};
use ark_std::{borrow::{ToOwned}, ops::Deref, vec::Vec, Zero, rand::{Rng,CryptoRng}, UniformRand};

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

/// Output and proof for a remask and shuffle operation.
/// 
/// Anyone could perform a remask and shuffle operation.  We treat only
/// the permutation being applied, the masking factors, and the randomness
/// used in the proof as secret here. 
///
/// We do not require any secret keys in particular, so `ShuffleMessage`s
/// can/do not sign themselves.  All players must apply the same remask
/// and shuffles though, so you'll want some signed wrapper for consensus
/// and spam prevention.
#[derive(Clone,CanonicalSerialize,CanonicalDeserialize)]
#[cfg_attr(feature="serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature="serde", serde(from = "CompressedChecked<Self>", into = "CompressedChecked<Self>"))]
pub struct ShuffleMessage<C: CurveGroup> {
    pub deck: Vec<MaskedCard<C>>,     // Should come first for bytes interfaces
    pub proof: ZKProofShuffle<C>,
}

impl<C: CurveGroup> Deref for ShuffleMessage<C> {
    type Target = [MaskedCard<C>];
    fn deref(&self) -> &[MaskedCard<C>] { &self.deck }
}
#[cfg(feature="serde")]
impl<C: CurveGroup> From<CompressedChecked<ShuffleMessage<C>>> for ShuffleMessage<C> {
    fn from(sig: CompressedChecked<ShuffleMessage<C>>) -> Self { sig.0 }
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
    ) -> Result<ShuffleMessage<C>, CryptoError> {
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
        Ok(ShuffleMessage { deck: masked_shuffled, proof })
    }

    /// Verify the mask-shuffle operation by `shuffle_and_remask`.
    ///
    /// You never need thus unless you size the shuffle differently
    /// than `mid_factor` does, aka padding and reveals. 
    pub fn raw_verify_shuffle<'a>(
        &self,
        shared_key: &AggregatePublicKey<C>,
        original_deck: &[MaskedCard<C>],
        shuffled: &'a ShuffleMessage<C>,
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

const SHUFFLE_RNG_SEED: &'static [u8] = b"Shuffle Proof";

impl<'p,C: CurveGroup> AggregatedPublicKeys<'p,C> {
    pub fn shuffle_and_remask<R: Rng+CryptoRng>( // shuffle_and_remask
        &self,
        rng: &mut R,
        deck: &[MaskedCard<C>],
    ) -> Result<ShuffleMessage<C>, CardProtocolError> {
        let size = deck.len();
        let masking_factors: Vec<Scalar<C>> = (0..size).map(|_| UniformRand::rand(rng)).collect();
        let permutation = Permutation::from_rng(rng,size);
        let size = mid_factor(size);
        Ok(self.parameters().raw_shuffle_and_remask(
            rng, self.aggregate_key(), deck, &masking_factors, &permutation, size, SHUFFLE_RNG_SEED
        )?)
    }

    /// Verify the mask-shuffle operation by `shuffle_and_remask`.
    pub fn verify_shuffle<'a>(
        &self,
        original_deck: &[MaskedCard<C>],
        shuffled_deck: &'a ShuffleMessage<C>,
    ) -> Result<&'a [MaskedCard<C>], CardProtocolError> {
        let size = mid_factor(original_deck.len());
        Ok(self.parameters().raw_verify_shuffle(
            self.aggregate_key(), original_deck, shuffled_deck, size, SHUFFLE_RNG_SEED
        )?)
    }
}
