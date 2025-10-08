
use super::*; // {UniformRand,thread_rng,CryptoError,Scalar,UnmaskedCard,CardParameters,RevealToken};

#[test]
fn test_verify_reveal() {
    let rng = &mut thread_rng();

    let parameters = CardParameters::setup(rng, 52);

    let key = parameters.player_keygen(rng);

    // let some_masked_card: MaskedCard = UniformRand::rand(rng);
    let some_unmasked_card: UnmaskedCard = UniformRand::rand(rng);
    // let some_masked_card = crate::masking::zero_mask(&some_unmasked_card);
    let r: Scalar = UniformRand::rand(rng);
    use crate::masking::Mask;
    let some_masked_card = some_unmasked_card.mask_card(&parameters.enc_parameters,&key.pk,&r);
    
    let mut reveal_message = parameters.prove_single_reveal_token(rng, &key, &some_masked_card);

    let revealed = parameters.verify_single_reveal(&reveal_message).unwrap();
    assert_eq!(revealed.1, some_unmasked_card.0);

    reveal_message.token = RevealToken::rand(rng);

    assert_eq!(
        parameters.verify_single_reveal(&reveal_message),
        Err(CryptoError::ProofVerificationError(
            "Chaum-Pedersen".into()
        ))
    )
}

#[test]
fn test_unmask() {
    let rng = &mut thread_rng();

    let num_of_players = 10;

    let parameters = CardParameters::setup(rng, 52);

    let (players, expected_shared_key) =
        raw_setup_players(rng, &parameters, num_of_players);

    let card = UnmaskedCard::rand(rng);
    let alpha = Scalar::rand(rng);
    let (masked, _) =
        parameters.prove_mask(rng, &expected_shared_key, &card, &alpha);

    let decryption_key = players.iter().map(
        |player| parameters.prove_single_reveal_token(rng,&player.1,&masked)
    ).collect::<Vec<_>>();

    let unmasked = parameters.unmask(&decryption_key, &masked).unwrap();

    assert_eq!(card, unmasked);

    let mut bad_decryption_key = decryption_key;
    bad_decryption_key[0].token = RevealToken::rand(rng);

    let failed_decryption = parameters.unmask(&bad_decryption_key, &masked);

    assert_eq!(
        failed_decryption,
        Err(CryptoError::ProofVerificationError("Chaum-Pedersen".into()).into())
    )
}

// prove_reveals_batch
// verify_reveals_batch
