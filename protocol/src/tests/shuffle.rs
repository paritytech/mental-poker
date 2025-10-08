
use super::*;
use cards_proofs::{error::CryptoError,utils::rand::sample_vector};

#[test]
fn test_shuffle() {
    let rng = &mut thread_rng();

    let num_of_players = 10;
    let deck_size = 52;

    let parameters = CardParameters::setup(rng, deck_size);

    let (_, apk) = setup_players(rng, &parameters, num_of_players);

    let deck: Vec<MaskedCard> = sample_vector(rng, deck_size);

    let shuffled = apk.shuffle_and_remask(
        rng,
        &deck,
    ).unwrap();

    assert!(
        apk.verify_shuffle(
            &deck,
            &shuffled
        ).is_ok()
    );

    let mut wrong = shuffled.clone();
    wrong.deck = sample_vector(rng, deck_size);

    assert_eq!(
        apk.verify_shuffle(
            &deck,
            &wrong,
        ),
        Err(CryptoError::ProofVerificationError("Hadamard Product (5.1)".into()).into())
    )
}

