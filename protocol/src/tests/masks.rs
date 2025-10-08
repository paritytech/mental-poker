
use super::*; // {thread_rng,CryptoError,Scalar,Curve,UnmaskedCard,MaskedCard,,,CardParameters,raw_setup_players};

type MaskingProof = cards_proofs::zkp::proofs::chaum_pedersen_dl_equality::proof::Proof<Curve>;

#[test]
fn test_verify_masking() {
    let rng = &mut thread_rng();

    let num_of_players = 10;

    let parameters = CardParameters::setup(rng, 52);
    let (m,n,padding) = crate::setup::mid_factor(52);
    assert_eq!(m, 4); // 2
    assert_eq!(n, 13); // 26
    assert_eq!(padding, 0);

    let (_, aggregate_key) = raw_setup_players(rng, &parameters, num_of_players);

    let some_card = UnmaskedCard::rand(rng);
    let some_random = Scalar::rand(rng);

    let (masked, masking_proof): (MaskedCard, MaskingProof) =
    parameters.prove_mask(rng, &aggregate_key, &some_card, &some_random);

    assert_eq!(
        Ok(()),
        parameters.verify_mask(
            &aggregate_key,
            &some_card,
            &masked,
            &masking_proof
        )
    );

    let wrong_masked = MaskedCard::rand(rng);

    assert_eq!(
        parameters.verify_mask(
            &aggregate_key,
            &some_card,
            &wrong_masked,
            &masking_proof
        ),
        Err(CryptoError::ProofVerificationError(
            "Chaum-Pedersen".into()
        ))
    )
}


#[test]
fn test_verify_remasking() {
    let rng = &mut thread_rng();

    let num_of_players = 10;

    let parameters = CardParameters::setup(rng, 52);

    let (_, aggregate_key) = setup_players(rng, &parameters, num_of_players);
    let aggregate_key = aggregate_key.aggregate_key();

    let some_masked_card = MaskedCard::rand(rng);
    let some_random = Scalar::rand(rng);

    let (remasked, remasking_proof): (MaskedCard, MaskingProof) = parameters.prove_remask(
        rng,
        &aggregate_key,
        &some_masked_card,
        &some_random,
    );

    assert_eq!(
        Ok(()),
        parameters.verify_remask(
            &aggregate_key,
            &some_masked_card,
            &remasked,
            &remasking_proof
        )
    );

    let wrong_output = MaskedCard::rand(rng);

    assert_eq!(
        parameters.verify_remask(
            &aggregate_key,
            &some_masked_card,
            &wrong_output,
            &remasking_proof
        ),
        Err(CryptoError::ProofVerificationError("Chaum-Pedersen".into()))
    )
}
