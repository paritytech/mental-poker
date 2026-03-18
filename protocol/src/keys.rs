
use crate::{
    Parameters,error::CardProtocolError, IntoTranscript,
};

use ark_ec::{AffineRepr,CurveGroup};
use ark_std::{io::{Read,Write}, borrow::{BorrowMut}, vec::Vec, rand::{Rng,CryptoRng}};
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize,SerializationError,Compress,Validate,Valid};

use cards_proofs::{
    error::CryptoError,
    homomorphic_encryption::{
        el_gamal, HomomorphicEncryptionScheme,
    },
    zkp::{
        proofs::schnorr_identification,
        ArgumentOfKnowledge,
    },
};

#[cfg(feature="serde")]
use ark_serialize::{CompressedChecked};

#[cfg(feature="serde")]
use serde::{Serialize, Deserialize};


pub type PlayerPublicKey<C> = el_gamal::PublicKey<C>;
pub type AggregatePublicKey<C> = el_gamal::PublicKey<C>;
pub type PlayerSecretKey<C> = el_gamal::SecretKey<C>;

/// Player's secret key.
///
/// We include the player's public key as a performance optimization
/// (or an interface simplification).
#[derive(Clone)]
// #[cfg_attr(feature="serde", derive(Serialize, Deserialize))]
// #[cfg_attr(feature="serde", serde(from = "CompressedChecked<Self>", into = "CompressedChecked<Self>"))]
pub struct PlayerKeypair<C: CurveGroup> {
    pub sk: PlayerSecretKey<C>,
    pub pk: PlayerPublicKey<C>,
}
// #[cfg(feature="serde")]
// impl<C: CurveGroup> From<CompressedChecked<PlayerKeypair<C>>> for PlayerKeypair<C> {
//     fn from(sig: CompressedChecked<PlayerKeypair<C>>) -> Self { sig.0 }
// }

impl<C: CurveGroup> CanonicalSerialize for PlayerKeypair<C> {
    fn serialize_with_mode<W: Write>(
        &self, writer: W, _: Compress,
    ) -> Result<(), SerializationError> {
        self.sk.serialize_compressed(writer)
    }
    fn serialized_size(&self, _: Compress) -> usize {
        self.sk.compressed_size()
    }
}


pub type ZKProofKeyOwnership<C> = schnorr_identification::proof::Proof<C>;


const KEY_OWN_RNG_SEED: &'static [u8] = b"Key Ownership Proof";

impl<C: CurveGroup> Parameters<C> {
    pub fn player_keygen<R: Rng+CryptoRng>(
        &self,
        system_rng: &mut R,
    ) -> PlayerKeypair<C> {
        let (pk, sk) = el_gamal::ElGamal::keygen(&self.enc_parameters, system_rng);
        PlayerKeypair { pk, sk }
    }

    pub fn player_from_secret(&self, sk: PlayerSecretKey<C>) -> PlayerKeypair<C> {
        use core::ops::Mul;
        let pk = self.enc_parameters.generator.mul(sk).into();
        PlayerKeypair { sk, pk }
    }

    pub fn deserialize_player<R: Read>(&self, reader: R) -> Result<PlayerKeypair<C>, SerializationError> {
        let sk = PlayerSecretKey::<C>::deserialize_compressed(reader) ?;
        Ok(self.player_from_secret(sk))
    }

    pub fn prove_key_ownership<R: Rng+CryptoRng>(
        &self,
        system_rng: &mut R,
        key: &PlayerKeypair<C>,
        player_public_info: impl IntoTranscript,
    ) -> ZKProofKeyOwnership<C> {
        let mut t = player_public_info.into_transcript();
        let t = t.borrow_mut();
        t.label(KEY_OWN_RNG_SEED);
        schnorr_identification::SchnorrIdentification::prove(
            system_rng,
            &self.enc_parameters.generator,
            &key.pk,
            &key.sk,
            t,
        ).expect("Infallible prover")
    }

    pub fn verify_key_ownership(
        &self,
        pk: &PlayerPublicKey<C>,
        player_public_info: impl IntoTranscript,
        proof: &ZKProofKeyOwnership<C>,
    ) -> Result<(), CryptoError> {
        let mut t = player_public_info.into_transcript();
        let t = t.borrow_mut();
        t.label(KEY_OWN_RNG_SEED);
        schnorr_identification::SchnorrIdentification::verify(
            &self.enc_parameters.generator, pk, proof, t,
        )
    }

    pub fn prove_player<R: Rng+CryptoRng>(
        &self,
        system_rng: &mut R,
        key: &PlayerKeypair<C>,
        player_public_info: impl IntoTranscript,
    ) -> PlayerHello<C> {
        let ownership_proof = self.prove_key_ownership(system_rng,&key,player_public_info);
        PlayerHello { pk: key.pk, ownership_proof }
    }

    pub fn generate_player<R: Rng+CryptoRng>(
        &self,
        system_rng: &mut R,
        player_public_info: impl IntoTranscript,
    ) -> (PlayerHello<C>, PlayerKeypair<C>) {
        let key = self.player_keygen(system_rng);
        (self.prove_player(system_rng,&key,player_public_info),key)
    }

    pub fn verify_player<'a>(
        &self,
        pk: &'a PlayerHello<C>,
        player_public_info: impl IntoTranscript,
    ) -> Result<&'a PlayerPublicKey<C>, CryptoError> {
        self.verify_key_ownership(&pk.pk, player_public_info, &pk.ownership_proof)?;
        Ok(&pk.pk)
    }
}

/// Player's public key and ownership proof.
///
/// As an interface simplification, we typically use this hello message
/// as the player's public key, but drop it in `AggregatedPublicKeys`.
#[derive(Clone,CanonicalDeserialize,CanonicalSerialize,Debug)]
#[cfg_attr(feature="serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature="serde", serde(from = "CompressedChecked<Self>", into = "CompressedChecked<Self>"))]
pub struct PlayerHello<C: CurveGroup> {
    pk: PlayerPublicKey<C>,
    ownership_proof: ZKProofKeyOwnership<C>,
}

#[cfg(feature="serde")]
impl<C: CurveGroup> From<CompressedChecked<PlayerHello<C>>> for PlayerHello<C> {
    fn from(sig: CompressedChecked<PlayerHello<C>>) -> Self { sig.0 }
}

impl<C: CurveGroup> PartialEq for PlayerHello<C> {
    fn eq(&self, other: &Self) -> bool { self.pk == other.pk }
}
impl<C: CurveGroup> Eq for PlayerHello<C> { }

impl<C: CurveGroup> core::ops::Deref for PlayerHello<C> {
    type Target = PlayerPublicKey<C>;
    fn deref(&self) -> &PlayerPublicKey<C> { &self.pk }
}

impl<C: CurveGroup> PlayerHello<C> {
    pub fn as_affine(&self) -> &<C as CurveGroup>::Affine { &self.pk }

    #[cfg(test)]
    pub(crate) fn corrupt_key(&mut self) {
        use ark_ec::AffineRepr;
        self.pk = <C as CurveGroup>::Affine::zero();
    }
}


impl<C: CurveGroup> Parameters<C> {
    pub fn create_aggregate_keys<'a>(&'a self) -> AggregatedPublicKeys<'a,C> {
        AggregatedPublicKeys {
            parameters: self,
            aggregated_key: C::Affine::zero(),
            players_public_keys: Vec::new(), // with_capacity(size_hint)
        }
    }
}

/// Aggregation of Public Key.
///
/// We enforce ownership proof verification here, becuase attacks exist otherwise.
#[derive(Clone,Debug)]
pub struct AggregatedPublicKeys<'p, C: CurveGroup> {
    parameters: &'p Parameters<C>,
    aggregated_key: C::Affine,
    players_public_keys: Vec<PlayerPublicKey<C>>,
}

/*
impl<C: CurveGroup> core::ops::Deref for AggregatedPublicKeys<C> {
    type Target = Parameters<C>;
    fn deref(&self) -> &Self::Target { &self.parameters }
}
*/

fn xy_key<C: CurveGroup>(p: &PlayerPublicKey<C>) -> Option<(C::BaseField, C::BaseField)> { p.xy() }

fn point_binary_search<C: CurveGroup>(ps: &[PlayerPublicKey<C>], p: &PlayerPublicKey<C>) -> Result<usize,usize> {
    ps.binary_search_by_key(&xy_key::<C>(p),xy_key::<C>)
}

impl<'p, C: CurveGroup> AggregatedPublicKeys<'p, C> {
    pub fn parameters(&self) -> &'p Parameters<C> {
        self.parameters
    }

    pub fn append(&self,t: &mut crate::Transcript) {
        t.append(&self.aggregated_key);
        t.append(&self.players_public_keys);
    }

    // #[allow(dead_code)]
    pub(crate) fn add_unchecked(&mut self, pk: PlayerPublicKey<C>) {
        self.aggregated_key = (self.aggregated_key + pk).into_affine();
        self.players_public_keys.push(pk);
    }

    /// Add a player's public key into the aggregation
    pub fn verify_n_add(
        &mut self,
        player: PlayerHello<C>,
        player_public_info: impl IntoTranscript,
    ) -> Result<(),CardProtocolError> { // TODO: Why not keep CryptoError?
        self.parameters.verify_key_ownership(&player.pk,player_public_info,&player.ownership_proof) ?;
        self.add_unchecked(player.pk);
        Ok(())
    }

    pub fn aggregate_key(&self) -> &AggregatePublicKey<C> {
        &self.aggregated_key
    }

    /// Returns players in addition order.
    pub fn players(&self) -> &[PlayerPublicKey<C>] {
        self.players_public_keys.as_slice()
    }

    /// Cannonicalize the player indices
    pub fn sort(&mut self) {
        self.players_public_keys.sort_by_key(xy_key::<C>);
    }

    pub fn player_index(&self, pk: &PlayerPublicKey<C>) -> Result<usize,CardProtocolError> {
        self.players().iter().position(|p| p==pk).ok_or(CardProtocolError::PlayerNotPresent)
    }

    /// Return an error early, instead of doing something like
    /// `self.players().iter().enumerate().filter_map(|(i,k)| k==p)`
    pub fn others_indices(&self, pk: &PlayerPublicKey<C>) -> Result<impl Iterator<Item=usize>,CardProtocolError> {
        let num_of_players = self.players().len();
        let index = self.player_index(pk)?;
        // Ok((0..index-1).chain(index..num_of_players))
        Ok((0..num_of_players).filter(move |i| *i != index))
    }

    /// Remove player by index.
    ///
    /// Returns removed palyer's public key.
    /// Panics if index is out of bounds.
    pub fn remove(&mut self, index: usize) -> PlayerPublicKey<C> {
        let pk = self.players_public_keys.remove(index);
        self.aggregated_key = (self.aggregated_key - pk).into_affine();
        pk
    }

    pub fn intersect<'q,'a>(&'a self, other: &AggregatedPublicKeys<'q,C>) -> impl Iterator<Item=&'a PlayerPublicKey<C>> {
        let mut other = other.players_public_keys.clone();
        other.sort_by_key(xy_key::<C>);
        let good = move |p: &&PlayerPublicKey<C>| point_binary_search::<C>(other.as_ref(),*p).is_ok();
        self.players_public_keys.iter().filter(good)
    }

    /// Return the partial mapping from new players to old player indices
    pub fn player_mapping<'q,'a>(&'a self, target: &AggregatedPublicKeys<'q,C>) -> Vec<Option<usize>> {
        target.players_public_keys.iter()
        .map(|t| self.players_public_keys.iter().position(|s| s==t))
        .collect()
    }

    /// Deserialize `AggregatedPublicKeys` from a serialized `Vec<PlayerPublicKey<C>>`.  // without checking anything.
    pub fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
        parameters: &'p Parameters<C>,
    ) -> Result<AggregatedPublicKeys<'p,C>, SerializationError> 
    {
        let players_public_keys = <Vec<PlayerPublicKey<C>> as CanonicalDeserialize>::deserialize_with_mode(reader,compress,validate)?;
        let apk: C = players_public_keys.iter().sum();
        Ok(AggregatedPublicKeys { parameters, aggregated_key: apk.into_affine(), players_public_keys, })
    }

    /// Deserialize `AggregatedPublicKeys` from a serialized `Vec<PlayerPublicKey<C>>`.   // without checking anything.
    pub fn deserialize_compressed<R: Read>(r: R, parameters: &'p Parameters<C>) -> Result<AggregatedPublicKeys<'p,C>,SerializationError> {
        Self::deserialize_with_mode(r,Compress::Yes,Validate::Yes,parameters)
    }
}

impl<'p, C: CurveGroup> CanonicalSerialize for AggregatedPublicKeys<'p, C> {
    /// One public key per player, plus 4 byte size.
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.players_public_keys.serialize_with_mode(writer,compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.players_public_keys.serialized_size(compress)
    }
}
impl<'p, C: CurveGroup> Valid for AggregatedPublicKeys<'p, C> {
    fn check(&self) -> Result<(), SerializationError> {
        self.players_public_keys.check()
    }
    fn batch_check<'a>(
        batch: impl Iterator<Item = &'a Self> + Send,
    ) -> Result<(), SerializationError>
    where Self: 'a, 
    {
        Valid::batch_check(batch.flat_map(|v| v.players_public_keys.iter()))        
    }
}

impl<'a,'p, C: CurveGroup> IntoIterator for &'a AggregatedPublicKeys<'p,C> {
    type Item = &'a PlayerPublicKey<C>;
    type IntoIter = core::slice::Iter<'a, PlayerPublicKey<C>>;
    fn into_iter(self) -> Self::IntoIter {
        self.players_public_keys.iter()
    }
}
