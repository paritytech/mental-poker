
use crate::{
    Parameters, error::{CardResult,CardProtocolError},
    UnmaskedCard, MaskedCard,
    keys::*,    
};

use ark_ec::{AffineRepr,CurveGroup};
use ark_std::{io::{Read,Write}, vec::Vec, rand::{Rng,CryptoRng}, Zero}; // io::{self,Write}
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize,SerializationError,Compress,Validate,Valid};

#[cfg(feature="serde")]
use ark_serialize::{CompressedChecked};

#[cfg(feature="serde")]
use serde::{Serialize, Deserialize};

use cards_proofs::{
    error::CryptoError,
    homomorphic_encryption::el_gamal,
    zkp::{
        proofs::chaum_pedersen_dl_equality,
        ArgumentOfKnowledge,
    },
};


/// A `RevealToken` is computed by players when they wish to reveal a given card.
/// These tokens can then be aggregated to reveal the card.
///
/// TODO:  But why use `el_gamal::Plaintext` here?
pub type RevealToken<C> = el_gamal::Plaintext<C>;

pub type ZKProofReveal<C> = chaum_pedersen_dl_equality::proof::Proof<C>;

const REVEAL_RNG_SEED: &'static [u8] = b"Reveal Proof";

pub fn reveal_unchecked<C: CurveGroup>(
    token: &RevealToken<C>,
    cipher: &MaskedCard<C>,
) -> UnmaskedCard<C> {
    let decrypted = cipher.1 - token.0;
    el_gamal::Plaintext(decrypted.into_affine())
}

pub fn update_masked_card<C: CurveGroup>(mc: &mut MaskedCard<C>, token: &RevealToken<C>) {
    let new = mc.1 - token.0;
    mc.1 = new.into_affine();
}

/// Find the card in a deck.
pub fn card_position<C: CurveGroup>(deck: &[UnmaskedCard<C>], card: &UnmaskedCard<C>) -> CardResult<usize> {
    if card.0.is_zero() {
        return Err(CardProtocolError::ZeroCard)
    }
    // TODO Make decks sorted
    // point_binary_search(&deck,&rc).map_err(|_| CardProtocolError::UnrecognizedCard)
    deck.iter().position(|dc| dc==card)
    // We have a dedicate error because this could be used in several places.
    // so WrongGame("Unrecognized card in eviction") fits poorly.
    .ok_or(CardProtocolError::UnrecognizedCard)
}

pub fn reveal_position<C: CurveGroup>(
    deck: &[UnmaskedCard<C>],
    masked_card: &MaskedCard<C>,
    revel_token: &RevealToken<C>,
) -> CardResult<usize> {
    let rc = reveal_unchecked(revel_token,masked_card);
    card_position(deck,&rc)
}

/// Reveals and proves the signer's `RevealToken` for a masked card.
///
/// Accumulate these from all signers to provably reveal the card.
#[derive(Clone,CanonicalSerialize,CanonicalDeserialize,Debug)]
pub struct RevealTnP<C: CurveGroup> {
    pub token: RevealToken<C>,
    pub proof: ZKProofReveal<C>,
}

/// Reveals and proves the signer's `RevealToken` for a masked card.
/// Accumulate these from all signers to provably reveal the card.
/// 
/// `RevealMessage`s contain their own self signature.
#[derive(Clone,CanonicalSerialize,CanonicalDeserialize,Debug)]
#[cfg_attr(feature="serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature="serde", serde(from = "CompressedChecked<Self>", into = "CompressedChecked<Self>"))]
pub struct RevealMessage<C: CurveGroup> {
    pub pk: PlayerPublicKey<C>,
    pub masked_card: MaskedCard<C>,
    pub tp: RevealTnP<C>,
}

impl<C: CurveGroup> core::ops::Deref for RevealMessage<C> {
    type Target = RevealTnP<C>;
    fn deref(&self) -> &RevealTnP<C> { &self.tp }
}
impl<C: CurveGroup> core::ops::DerefMut for RevealMessage<C> {
    fn deref_mut(&mut self) -> &mut RevealTnP<C> { &mut self.tp }
}

#[cfg(feature="serde")]
impl<C: CurveGroup> From<CompressedChecked<RevealMessage<C>>> for RevealMessage<C> {
    fn from(sig: CompressedChecked<RevealMessage<C>>) -> Self { sig.0 }
}

impl<C: CurveGroup> PlayerKeypair<C> {
    pub fn compute_reveal_token(&self, masked_card: &MaskedCard<C>) -> RevealToken<C> {
        el_gamal::Plaintext(masked_card.0.into().mul(self.sk).into_affine())
    }

    // pub fn mask_from_sk(&self, masked_card: &MaskedCard<C>) -> MaskedCard<C> {
    //     el_gamal::Cipertext(masked_card.0, self.compute_reveal_token(masked_card).0);
    // }
}

impl<C: CurveGroup> crate::Parameters<C> {
    pub fn prove_reveal<R: Rng+CryptoRng>(
        &self,
        rng: &mut R,
        key: &PlayerKeypair<C>,
        masked_card: &MaskedCard<C>,
    ) -> RevealTnP<C> {
        let token: RevealToken<C> = key.compute_reveal_token(masked_card);

        // Map to Chaum-Pedersen parameters
        let cp_parameters = chaum_pedersen_dl_equality::Parameters::new(
            &self.enc_parameters.generator,
            &masked_card.0,
        );

        // Map to Chaum-Pedersen parameters
        let cp_statement = chaum_pedersen_dl_equality::Statement::new(&key.pk, &token.0);

        let proof = chaum_pedersen_dl_equality::DLEquality::prove(
            rng,
            &cp_parameters,
            &cp_statement,
            &key.sk,
            REVEAL_RNG_SEED,
        ).expect("Infallible prover");

        RevealTnP { token, proof }
    }

    pub fn verify_reveal<'a>(
        &self,
        pk: &PlayerPublicKey<C>,
        reveal: &'a RevealTnP<C>,
        masked_card: &MaskedCard<C>,
    ) -> Result<&'a RevealToken<C>, CryptoError> {
        // Map to Chaum-Pedersen parameters
        let cp_parameters = chaum_pedersen_dl_equality::Parameters::new(
            &self.enc_parameters.generator,
            &masked_card.0,
        );

        // Map to Chaum-Pedersen parameters
        let cp_statement = chaum_pedersen_dl_equality::Statement::new(pk, &reveal.token.0);

        chaum_pedersen_dl_equality::DLEquality::verify(
            &cp_parameters,
            &cp_statement,
            &reveal.proof,
            REVEAL_RNG_SEED,
        )?;

        Ok(&reveal.token)
    }

    pub fn prove_single_reveal_token<R: Rng+CryptoRng>(
        &self,
        rng: &mut R,
        key: &PlayerKeypair<C>,
        masked_card: &MaskedCard<C>,
    ) -> RevealMessage<C> {
        let tp = self.prove_reveal(rng,key,masked_card);
        RevealMessage { pk: key.pk.clone(), masked_card: masked_card.clone(), tp, }
    }

    pub fn verify_single_reveal<'a>(
        &self,
        reveal: &'a RevealMessage<C>,
    ) -> Result<MaskedCard<C>,CryptoError> {
        self.verify_reveal(&reveal.pk,&reveal.tp,&reveal.masked_card)?;
        let mut masked_card = reveal.masked_card.clone();
        update_masked_card(&mut masked_card, &reveal.token);
        Ok(masked_card)
    }

    pub fn unmask(
        &self,
        decryption_messages: &[RevealMessage<C>],
        masked_card: &MaskedCard<C>,
    ) -> CardResult<UnmaskedCard<C>> {
        let mut aggregate_token = RevealToken::<C>::zero();
        for reveal_message in decryption_messages {
            if masked_card != &reveal_message.masked_card {
                return Err(CardProtocolError::WrongCard);
            }
            self.verify_single_reveal(reveal_message)?;
            aggregate_token = aggregate_token + reveal_message.token;
        }
        Ok(reveal_unchecked(&aggregate_token,masked_card))
    }
}

impl<'p,C: CurveGroup>  AggregatedPublicKeys<'p,C> {
    pub fn accumulate_reveals(&self, masked_card: MaskedCard<C>) -> AccumulateReveals<'p,C> {
        AccumulateReveals {
            parameters: self.parameters(),
            remaining_key: self.aggregate_key().into_group(),
            masked_card,
            token: RevealToken::<C>::zero(),
        }
    }
}

/// Verify and accumulate `RevealMessage`s
///
#[derive(Clone)]
pub struct AccumulateReveals<'p,C: CurveGroup> {
    pub(crate) parameters: &'p crate::Parameters<C>,
    pub(crate) remaining_key: C,
    pub(crate) masked_card: MaskedCard<C>,
    pub(crate) token: RevealToken<C>,
}

impl<'p,C: CurveGroup>  AccumulateReveals<'p,C> {
    pub fn parameters(&self) -> &'p crate::Parameters<C> { self.parameters }
    pub fn remaining_key(&self) -> &C { &self.remaining_key }
    pub fn masked_card(&self) -> &MaskedCard<C> { &self.masked_card }
    pub fn token(&self) -> &RevealToken<C> { &self.token }

    /// Prove your reveal component for a draw 
    ///
    /// You must call this whenever a drawn card is not intended for you.
    pub fn prove_reveal<R: Rng+CryptoRng>(
        &self,
        rng: &mut R,
        sk: &PlayerKeypair<C>,
    ) -> RevealMessage<C> {
        self.parameters.prove_single_reveal_token(rng,sk,&self.masked_card)
    }

    pub fn add_reveal(&mut self, reveal_message: &RevealMessage<C>) -> CardResult<()> {
        if self.masked_card != reveal_message.masked_card {
            return Err(CardProtocolError::WrongCard);
        }
        self.parameters.verify_single_reveal(reveal_message)?;
        self.token = self.token + reveal_message.token;
        self.remaining_key = self.remaining_key - reveal_message.pk;
        Ok(())
    }

    /// Returns the remaining aggregate publickey and remaining ciphertext.
    ///    
    /// If the remaining aggregate publickey passes `.is_zero()` then
    /// the remaining ciphertext converts to
    pub fn status(&self) -> (AggregatePublicKey<C>,MaskedCard<C>) {
        let mut masked_card = self.masked_card.clone();
        update_masked_card(&mut masked_card,&self.token);
        (self.remaining_key.into_affine(),masked_card)
    }

    pub fn is_completed(&self) -> bool { self.remaining_key.is_zero() }

    pub fn completed(&self) -> Option<UnmaskedCard<C>> {
        if !self.is_completed() { return None; }
        Some(reveal_unchecked(&self.token,&self.masked_card))
    }

    pub fn is_completed_for(&self, pk: &PlayerPublicKey<C>) -> bool {
        self.remaining_key == pk.into_group()
    }

    pub fn completed_for(&self, pk: &PlayerPublicKey<C>) -> Option<MaskedCard<C>> {
        let status = self.status();
        if &status.0 != pk { return None; }        
        Some(status.1)
    }

    /// Deserialize `AggregatedPublicKeys` from a serialized `Vec<PlayerPublicKey<C>>`,
    /// without checking anything.
    pub fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
        parameters: &'p Parameters<C>,
    ) -> Result<AccumulateReveals<'p,C>,SerializationError> {
        Ok(AccumulateReveals {
            parameters,
            remaining_key: CanonicalDeserialize::deserialize_with_mode(&mut reader,compress,validate)?,
            masked_card: CanonicalDeserialize::deserialize_with_mode(&mut reader,compress,validate)?,
            token: CanonicalDeserialize::deserialize_with_mode(&mut reader,compress,validate)?,
        })
    }

    /// Deserialize `AggregatedPublicKeys` from a serialized `Vec<PlayerPublicKey<C>>`.   // without checking anything.
    pub fn deserialize_compressed<R: Read>(r: R, parameters: &'p Parameters<C>) -> Result<AccumulateReveals<'p,C>,SerializationError> {
        Self::deserialize_with_mode(r,Compress::Yes,Validate::Yes,parameters)
    }
}

impl<'p, C: CurveGroup> CanonicalSerialize for AccumulateReveals<'p,C> {
    /// One public key per player, plus 4 byte size.
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.remaining_key.serialize_with_mode(&mut writer,compress)?;
        self.masked_card.serialize_with_mode(&mut writer,compress)?;
        self.token.serialize_with_mode(&mut writer,compress)
    }

    /// If `c = C::compressed_size()`, often 32 bytes, then
    /// `AccumulateReveals` serializes in `4 c` bytes when compressed.
    fn serialized_size(&self, compress: Compress) -> usize {
        self.remaining_key.serialized_size(compress)
        + self.masked_card.serialized_size(compress)
        + self.token.serialized_size(compress)
    }
}
impl<'p, C: CurveGroup> Valid for AccumulateReveals<'p,C> {
    fn check(&self) -> Result<(), SerializationError> {
        self.remaining_key.check()?;
        self.masked_card.check()?;
        self.token.check()
    }
}

/// Reveals and proves the signer's `RevealToken`s for a batch of masked card.
/// Accumulate these from all signers to provably reveal the card.
/// 
/// `RevealsMerged`s contain their own self signature.
/// TODO:  Use batch proving or verification.
#[derive(Clone,CanonicalSerialize,CanonicalDeserialize)]
#[cfg_attr(feature="serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature="serde", serde(from = "CompressedChecked<Self>", into = "CompressedChecked<Self>"))]
pub struct RevealsMerged<C: CurveGroup> {
    pub pk: PlayerPublicKey<C>,
    // pub set: Vec<RevealTnP<C>>,
    pub tokens: Vec<RevealToken<C>>,
    pub proof: ZKProofReveal<C>,
}

#[cfg(feature="serde")]
impl<C: CurveGroup> From<CompressedChecked<RevealsMerged<C>>> for RevealsMerged<C> {
    fn from(sig: CompressedChecked<RevealsMerged<C>>) -> Self { sig.0 }
}

fn affines_from_tokens<C: CurveGroup>(tokens: &[RevealToken<C>]) -> &[C::Affine] {
    unsafe { core::mem::transmute(tokens) }
}

impl<C: CurveGroup> crate::Parameters<C> {
    /// Create the player's reveal proof a batch of masked cards
    pub fn prove_merged_reveals<'a,R: Rng+CryptoRng>(
        &self,
        rng: &mut R,
        key: &PlayerKeypair<C>,
        masked_cards: impl IntoIterator<Item=&'a MaskedCard<C>>,
    ) -> RevealsMerged<C> {
        // let set = masked_cards.into_iter()
        // .map(|mc| self.prove_reveal(rng,key,mc)).collect();
        // RevealsMerged { pk: key.pk.clone(), set }

        let (h,tokens): (Vec<_>,Vec<_>) = masked_cards.into_iter().map(|masked_card| {
            let token: RevealToken<C> = key.compute_reveal_token(masked_card);
            (masked_card.0, token)
        }).unzip();

        let cp_parameters = chaum_pedersen_dl_equality::Parameters {
            g: &self.enc_parameters.generator, h: h.as_slice()
        };

        let cp_statement = chaum_pedersen_dl_equality::Statement(&key.pk, affines_from_tokens(tokens.as_slice()));

        let proof = chaum_pedersen_dl_equality::DLEquality::prove(
            rng,
            &cp_parameters,
            &cp_statement,
            &key.sk,
            REVEAL_RNG_SEED,
        ).expect("Infallible prover");

        RevealsMerged { pk: key.pk.clone(), tokens, proof, }
    }

    /// Create a player's merged reveal proof of a batch of masked cards
    pub fn verify_merged_reveals<'a,'b>(
        &self,
        reveals: &'a RevealsMerged<C>,
        masked_cards: impl IntoIterator<Item=&'b MaskedCard<C>>,
    ) -> Result<&'a [RevealToken<C>], CryptoError> {
        // let RevealsMerged { pk, set } = reveals;
        // for (tp,mc) in set.iter().zip(masked_cards) {
        //     self.verify_reveal(pk,tp,mc)?;
        // }
        // Ok(())

        let h: Vec<_> = masked_cards.into_iter().map(|masked_card| masked_card.0).collect();
        let cp_parameters = chaum_pedersen_dl_equality::Parameters {
            g: &self.enc_parameters.generator, h: h.as_slice()
        };

        let cp_statement = chaum_pedersen_dl_equality::Statement(&reveals.pk, affines_from_tokens(reveals.tokens.as_slice()));

        chaum_pedersen_dl_equality::DLEquality::verify(
            &cp_parameters,
            &cp_statement,
            &reveals.proof,
            REVEAL_RNG_SEED,
        )?;

        Ok(&reveals.tokens)
    }

    pub fn verify_merged_n_partial_unmasks<'a>(
        &self,
        reveals: &'a RevealsMerged<C>,
        masked_cards: &'a mut [MaskedCard<C>],
    ) -> Result<(), CryptoError> {
        let tokens = self.verify_merged_reveals(reveals,&*masked_cards)?;
        for (token,mc) in tokens.iter().zip(masked_cards) {
            update_masked_card(mc,&token);
        }
        Ok(())
    }
}

