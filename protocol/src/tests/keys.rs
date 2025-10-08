
use super::*;

#[test]
fn test_generate_and_verify_key() {
    let rng = &mut thread_rng();

    let parameters = CardParameters::setup(rng, 52);

    let key = parameters.player_keygen(rng);
    let player_name: &[u8] = b"Alice";

    let p1_keyproof = parameters.prove_key_ownership(rng, &key, player_name);

    parameters.verify_key_ownership(&key.pk, player_name, &p1_keyproof).unwrap();

    let other_key = crate::keys::PlayerKeypair { pk: key.pk.clone(), sk: Scalar::rand(rng) };
    let wrong_proof = parameters.prove_key_ownership(rng, &other_key, player_name);

    assert_eq!(
        parameters.verify_key_ownership(&key.pk, player_name, &wrong_proof),
        Err(CryptoError::ProofVerificationError("Schnorr Identification".into()))
    )
}

#[test]
fn test_aggregate_keys() {
    let rng = &mut thread_rng();

    let num_of_players = 10;

    let parameters = CardParameters::setup(rng, 52);

    let (mut players, expected_shared_key) = raw_setup_players(rng, &parameters, num_of_players);

    let mut aggregate = parameters.create_aggregate_keys();
    for (pk,_sk,name) in &players {
        assert!(aggregate.verify_n_add(pk.clone(),name).is_ok());
    }
    assert_eq!(aggregate.aggregate_key(), &expected_shared_key);

    let five = players[5].0.clone();
    players[5].0.corrupt_key();
    for (pk,_sk,name) in players {
        let r = aggregate.verify_n_add(pk.clone(),&name);
        if pk == five {
            assert_eq!(
                r,
                Err(CryptoError::ProofVerificationError("Schnorr Identification".into()).into())
            )        
        }
    }
}
