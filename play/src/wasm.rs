use wasm_bindgen::prelude::*;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use cards_deck::Deck;

use crate::*;

fn ser<T: CanonicalSerialize>(val: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    val.serialize_compressed(&mut bytes)
        .expect("serialization failed");
    bytes
}

fn de<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T, JsError> {
    T::deserialize_compressed(bytes).map_err(|e| JsError::new(&format!("{e}")))
}

/// Generate a player keypair. `name` is the raw 32-byte AccountId
/// (SCALE-encoded AccountId32 = raw bytes for fixed-size arrays).
///
/// Returns: `[hello_len as u32 LE][hello_bytes][keypair_bytes]`
#[wasm_bindgen]
pub fn generate_player(name: &[u8]) -> Result<Vec<u8>, JsError> {
    let (hello, keypair) = crate::generate_player(name);
    let hello_bytes = ser(&hello);
    let keypair_bytes = ser(&keypair);
    let hello_len = (hello_bytes.len() as u32).to_le_bytes();
    let mut out = hello_len.to_vec();
    out.extend(hello_bytes);
    out.extend(keypair_bytes);
    Ok(out)
}

/// Extract the serialized PlayerHello from generate_player output.
/// This is what gets submitted on-chain via `register_player`.
#[wasm_bindgen]
pub fn extract_hello(player_data: &[u8]) -> Result<Vec<u8>, JsError> {
    if player_data.len() < 4 {
        return Err(JsError::new("player data too short"));
    }
    let hello_len = u32::from_le_bytes(
        player_data[..4]
            .try_into()
            .map_err(|_| JsError::new("bad length prefix"))?,
    ) as usize;
    if player_data.len() < 4 + hello_len {
        return Err(JsError::new("player data truncated"));
    }
    Ok(player_data[4..4 + hello_len].to_vec())
}

/// Extract the serialized PlayerKeypair from generate_player output.
/// Keep this secret — needed for shuffling reveals.
#[wasm_bindgen]
pub fn extract_keypair(player_data: &[u8]) -> Result<Vec<u8>, JsError> {
    if player_data.len() < 4 {
        return Err(JsError::new("player data too short"));
    }
    let hello_len = u32::from_le_bytes(
        player_data[..4]
            .try_into()
            .map_err(|_| JsError::new("bad length prefix"))?,
    ) as usize;
    if player_data.len() < 4 + hello_len {
        return Err(JsError::new("player data truncated"));
    }
    Ok(player_data[4 + hello_len..].to_vec())
}

/// Create zero-masked deck from the first `count` static deck plaintexts.
/// Returns serialized `Vec<MaskedCard>`.
#[wasm_bindgen]
pub fn zero_mask_deck(count: u32) -> Result<Vec<u8>, JsError> {
    let count = count as usize;
    if count > DECK.len() {
        return Err(JsError::new(&format!(
            "count {} exceeds max deck size {}",
            count,
            DECK.len()
        )));
    }
    let plaintexts = &DECK[..count];
    let masked = cards_protocol::masking::zero_mask_cards(plaintexts);
    Ok(ser(&masked))
}

/// Shuffle the deck using aggregate public keys.
///
/// `agg_key_bytes`: serialized AggregatedPublicKeys (from chain's AggregateKeyData storage).
/// `deck_bytes`: serialized `Vec<MaskedCard>` (from chain's CurrentDeck storage).
///
/// Returns serialized `ShuffleMessage` (deck + ZK proof), to submit via `submit_shuffle`.
#[wasm_bindgen]
pub fn shuffle_deck(agg_key_bytes: &[u8], deck_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    let apk: AggregatedPublicKeys = de(agg_key_bytes)?;
    let deck: Vec<MaskedCard> = de(deck_bytes)?;
    let shuffle_msg = apk
        .shuffle_and_remask_(&deck)
        .map_err(|e| JsError::new(&format!("shuffle failed: {e:?}")))?;
    Ok(ser(&shuffle_msg))
}

/// Produce a reveal token for a single masked card.
///
/// `keypair_bytes`: serialized PlayerKeypair (from extract_keypair).
/// `card_bytes`: serialized MaskedCard (from get_masked_card).
///
/// Returns serialized `RevealMessage`. Submit on-chain via `submit_reveal`,
/// or keep locally if this player is the card recipient.
#[wasm_bindgen]
pub fn prove_reveal_token(keypair_bytes: &[u8], card_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    let keypair: PlayerKeypair = de(keypair_bytes)?;
    let card: MaskedCard = de(card_bytes)?;
    let reveal_msg = PARAMS.prove_single_reveal_token(&mut getrandom_or_panic(), &keypair, &card);
    Ok(ser(&reveal_msg))
}

/// Unmask a card given all N reveal messages (one per player).
///
/// `reveal_msgs_bytes`: serialized `Vec<RevealMessage>` (all N players' reveals).
/// `card_bytes`: serialized `MaskedCard` being revealed.
///
/// Returns the deck position as u32. Use `card_type()` in TS to map to game meaning.
#[wasm_bindgen]
pub fn unmask_card(reveal_msgs_bytes: &[u8], card_bytes: &[u8]) -> Result<u32, JsError> {
    let reveals: Vec<RevealMessage> = de(reveal_msgs_bytes)?;
    let card: MaskedCard = de(card_bytes)?;
    let unmasked = PARAMS
        .unmask(&reveals, &card)
        .map_err(|e| JsError::new(&format!("unmask failed: {e:?}")))?;
    let point = unmasked.0;
    let position = deck_secp256k1::DECK_SECP256K1
        .decode(&point)
        .ok_or_else(|| JsError::new("card not in deck"))?;
    Ok(position as u32)
}

/// Extract a single masked card from a serialized deck by index.
/// Returns serialized `MaskedCard`.
#[wasm_bindgen]
pub fn get_masked_card(deck_bytes: &[u8], index: u32) -> Result<Vec<u8>, JsError> {
    let deck: Vec<MaskedCard> = de(deck_bytes)?;
    let card = deck.get(index as usize).ok_or_else(|| {
        JsError::new(&format!(
            "card index {} out of range {}",
            index,
            deck.len()
        ))
    })?;
    Ok(ser(card))
}

/// Extract the shuffled deck from a serialized ShuffleMessage.
/// Returns serialized `Vec<MaskedCard>`.
#[wasm_bindgen]
pub fn get_shuffled_deck(shuffle_msg_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    let shuffle_msg: ShuffleMessage = de(shuffle_msg_bytes)?;
    Ok(ser(&shuffle_msg.deck))
}

/// Return the number of cards in a serialized `Vec<MaskedCard>`.
#[wasm_bindgen]
pub fn deck_card_count(deck_bytes: &[u8]) -> Result<u32, JsError> {
    let deck: Vec<MaskedCard> = de(deck_bytes)?;
    Ok(deck.len() as u32)
}

/// Return the maximum supported deck size (200 for secp256k1).
#[wasm_bindgen]
pub fn max_deck_size() -> u32 {
    DECK.len() as u32
}
