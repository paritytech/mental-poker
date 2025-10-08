
use crate::error::*;
use crate::zkp::proofs::chaum_pedersen_dl_equality::{self as module,ERROR,DLEquality};
use crate::zkp::ArgumentOfKnowledge;
use ark_ec::CurveGroup;
use ark_std::{rand::thread_rng, UniformRand};
use rand::{prelude::ThreadRng, Rng};

type Curve = ark_secp256k1::Projective;
type Point = ark_secp256k1::Affine;
type Scalar = ark_secp256k1::Fr;
type Parameters<'a> = module::Parameters<'a, Curve>;

fn setup<R: Rng>(rng: &mut R) -> (Point, Point) {
    (
        Curve::rand(rng).into_affine(),
        Curve::rand(rng).into_affine(),
    )
}

fn test_template() -> (ThreadRng, Point, Point, Scalar) {
    let mut rng = thread_rng();
    let (g, h) = setup(&mut rng);
    let secret = Scalar::rand(&mut rng);

    (rng, g, h, secret)
}

#[test]
fn test_honest_prover() {
    use ark_std::ops::Mul;

    let (mut rng, g, h, secret) = test_template();

    let point_a = g.mul(secret).into_affine();
    let point_b = h.mul(secret).into_affine();

    let crs = Parameters::new(&g, &h);
    let statement = module::Statement::<Curve>::new(
        &point_a, &point_b,
    );
    let witness = &secret;

    let seed = b"Initialised with some input";
    let proof = DLEquality::<Curve>::prove(
        &mut rng,
        &crs,
        &statement,
        &witness,
        seed,
    )
    .unwrap();

    assert_eq!(
        DLEquality::<Curve>::verify(&crs, &statement, &proof, seed),
        Ok(())
    );

    assert_ne! {point_a, point_b};
}

#[test]
fn test_malicious_prover() {
    use ark_std::ops::Mul;

    let (mut rng, g, h, secret) = test_template();

    let point_a = g.mul(secret).into_affine();
    let point_b = h.mul(secret).into_affine();

    let another_scalar = Scalar::rand(&mut rng);

    let crs = Parameters::new(&g, &h);
    let statement = module::Statement::<Curve>::new(
        &point_a, &point_b,
    );

    let wrong_witness = &another_scalar;

    let seed = b"Initialised with some input";
    let invalid_proof = DLEquality::<Curve>::prove(
        &mut rng,
        &crs,
        &statement,
        &wrong_witness,
        seed,
    )
    .unwrap();

    assert_eq!(
        DLEquality::<Curve>::verify(
            &crs,
            &statement,
            &invalid_proof,
            seed
        ),
        Err(CryptoError::ProofVerificationError(ERROR.into()))
    );
}

