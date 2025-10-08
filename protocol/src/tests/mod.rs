
use ark_ec::{AffineRepr,CurveGroup};
use ark_ff::UniformRand;
use ark_std::{iter::Iterator, vec::Vec, rand::{Rng,CryptoRng}};

use cards_proofs::{error::CryptoError};
use rand::thread_rng;

// Choose elliptic curve setting
pub(crate) type Curve = ark_secp256k1::Projective;
pub(crate) type Scalar = ark_secp256k1::Fr;

// Instantiate concrete type for our card protocol
pub(crate) type CardParameters = crate::Parameters<Curve>;

pub(crate) type MaskedCard = crate::MaskedCard<Curve>;
pub(crate) type UnmaskedCard = crate::UnmaskedCard<Curve>;
pub(crate) type RevealToken = crate::reveal::RevealToken<Curve>;

pub(crate) type Hello = crate::keys::PlayerHello<Curve>;
pub(crate) type PublicKey = crate::keys::PlayerPublicKey<Curve>;
// type SecretKey = crate::keys::PlayerSecretKey<Curve>;
pub(crate) type Keypair = crate::keys::PlayerKeypair<Curve>;
pub(crate) type AggregatedPublicKeys<'a> = crate::keys::AggregatedPublicKeys<'a,Curve>;

// TODO: Tests
// pub(crate) type RevealMessage = crate::reveal::RevealMessage<Curve>;
// pub(crate) type AccumulateReveals<'p> = crate::reveal::AccumulateReveals<'p,Curve>;


type PlayerInfo = [u8; 32];

mod keys;
mod shuffle;
mod reveal;
mod masks;

// #[test]
// fn size_of_parameters() {
//     assert_eq!(core::mem::size_of::<CardParameters>(),352);
//     panic!("!!! size_of::<Parameters<ark_bls12_377::G1>() = {} !!!",core::mem::size_of::<CardParameters>());
// }

/// Setup `n` players. We use a Scalar to represent player public information
pub(crate) fn raw_setup_players<R: Rng+CryptoRng>(
    rng: &mut R,
    parameters: &CardParameters,
    num_of_players: usize,
) -> (Vec<(Hello, Keypair, PlayerInfo)>, PublicKey) {
    let mut players: Vec<(Hello, Keypair, PlayerInfo)> = Vec::with_capacity(num_of_players);
    let mut expected_shared_key = PublicKey::zero();

    for _ in 0..num_of_players {
        let player_info = PlayerInfo::rand(rng);
        let (pk, sk) = parameters.generate_player(rng,&player_info);
        expected_shared_key = (expected_shared_key + pk.as_affine()).into_affine();
        players.push((pk, sk, player_info));
    }

    (players, expected_shared_key)
}

pub(crate) fn setup_players<'p,R: Rng+CryptoRng>(
    rng: &mut R,
    parameters: &'p CardParameters,
    num_of_players: usize,
) -> (Vec<Keypair>, AggregatedPublicKeys<'p>) {
    let size = parameters.parameters_size();
    let (_m,n,_) = crate::setup::mid_factor(size);
    assert!(num_of_players <= n, "num_of_players = {},  n = {}",num_of_players,n);
    let mut players: Vec<Keypair> = Vec::with_capacity(num_of_players);
    let mut apk = parameters.create_aggregate_keys();

    for _ in 0..num_of_players {
        let (pk,sk) = parameters.generate_player(rng,b"");
        let _ = apk.verify_n_add(pk,b"");
        players.push(sk);
    }

    (players, apk)
}
