//! An example that showcases how the prover time and proof size are affected by the parameter selection.
//! As per the Bayer-Groth paper, for a deck of $N = m \times n$ cards:
//! - the prover performs m*N exponentiations
//! - the proof is approximately 6m*|G|+4n*|Z| where |G| is the size of a EC point and |Z| is the size of a scalar
//! (note that this is because we are not using the FFT-like improvement suggested in the paper)
//! 
//! Analysis: increasing m will always increase the prover time. Assuming |G| ≈≈ 2*|Z|, proof size is approx 12m+4n and will
//! be minimised when m ≈≈ n/3.
//! 
//! Run the example `cargo run --example parameter_selection --release` and notice how proof size hits a minimum at m=10, n=30

use anyhow::anyhow;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use cards_protocol::MaskedCard;
use byte_unit::Byte;
use cards_proofs::utils::permutation::Permutation;
use cards_proofs::utils::rand::sample_vector;
use rand::{thread_rng, Rng,CryptoRng};
use std::time::Instant;

// Choose elliptic curve setting
type Curve = ark_secp256k1::Projective;
type Scalar = ark_secp256k1::Fr;

// Instantiate concrete type for our card protocol
type CardParameters = cards_protocol::Parameters<Curve>;

const NUMBER_OF_CARDS: usize = 300;

fn main() -> anyhow::Result<()> {
    let mut rng = thread_rng();

    let deck: Vec<MaskedCard<Curve>> = sample_vector(&mut rng, NUMBER_OF_CARDS);
    let shared_key = Curve::rand(&mut rng);
    let blinding_factors: Vec<Scalar> = sample_vector(&mut rng, NUMBER_OF_CARDS);
    let permutation = Permutation::from_rng(&mut rng, NUMBER_OF_CARDS);

    let m_values: Vec<usize> = vec![2, 6, 10, 12, 30];
    let n_values: Vec<usize> = vec![150, 50, 30, 25, 10];

    for (&m, &n) in m_values.iter().zip(n_values.iter()) {
        benchmark_parameters(
            &deck,
            m,
            n,
            &shared_key,
            &blinding_factors,
            &permutation,
            &mut rng,
        )?;
    }

    Ok(())
}

fn benchmark_parameters<R: Rng+CryptoRng>(
    deck: &Vec<MaskedCard<Curve>>,
    m: usize,
    n: usize,
    shared_key: &Curve,
    masking_factors: &Vec<Scalar>,
    permutation: &Permutation,
    rng: &mut R,
) -> anyhow::Result<()> {
    if deck.len() != m * n {
        return Err(anyhow!("Parameters do not match the deck size."));
    }

    println!("\n---------------------------------------------------");
    println!(
        "  Running a shuffle with parameters m = {} and n = {}",
        m, n
    );

    let parameters = CardParameters::setup(rng, m * n);

    let prover_start_time = Instant::now();
    let shuffled = parameters.raw_shuffle_and_remask(
        rng,
        &shared_key.into_affine(),
        deck,
        masking_factors,
        permutation,
        (m, n, 0),
        b"",
    )?;
    let prover_end_time = Instant::now();
    let prover_duration = prover_end_time - prover_start_time;

    println!("    Prover time: {} seconds", prover_duration.as_secs_f32());
    println!(
        "    Proof size: {}\n",
        Byte::from_bytes(shuffled.proof.compressed_size() as u128).get_appropriate_unit(false)
    );

    Ok(())
}
