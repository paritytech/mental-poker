use wasm_bindgen::prelude::*;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use cards_deck::Deck;

// Alias inner types to avoid shadowing our exported wasm_bindgen structs.
use crate::PlayerHello as InnerPlayerHello;
use crate::PlayerKeypair as InnerPlayerKeypair;
use crate::MaskedCard as InnerMaskedCard;
use crate::ShuffleMessage as InnerShuffleMessage;
use crate::RevealMessage as InnerRevealMessage;
use crate::AggregatedPublicKeys as InnerAggregatedPublicKeys;
use crate::{DECK, PARAMS, CardProtocolError};

fn ser<T: CanonicalSerialize>(val: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    val.serialize_compressed(&mut bytes)
        .expect("serialization failed");
    bytes
}

fn de<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T, JsError> {
    T::deserialize_compressed(bytes).map_err(|e| JsError::new(&format!("{e}")))
}

fn proto_err(e: CardProtocolError) -> JsError {
    JsError::new(&format!("{e:?}"))
}

// ---------------------------------------------------------------------------
// Opaque wrapper types
// ---------------------------------------------------------------------------

/// Result of key generation — contains a player's hello message and secret keypair.
#[wasm_bindgen]
pub struct PlayerData {
    hello: InnerPlayerHello,
    keypair: InnerPlayerKeypair,
}

/// A player's public hello message (public key + proof-of-knowledge).
/// Submit on-chain via `register_player`.
#[wasm_bindgen]
pub struct PlayerHello(InnerPlayerHello);

/// A player's secret keypair. Never leaves WASM — used to produce reveals.
#[wasm_bindgen]
pub struct PlayerKeypair(InnerPlayerKeypair);

/// A deck of masked (encrypted) cards.
#[wasm_bindgen]
pub struct MaskedDeck(Vec<InnerMaskedCard>);

/// A single masked (encrypted) card.
#[wasm_bindgen]
pub struct MaskedCard(InnerMaskedCard);

/// Aggregated public keys for all players in a game.
/// Constructed from on-chain data after all players register.
#[wasm_bindgen]
pub struct AggregatedKeys(InnerAggregatedPublicKeys);

/// A shuffle message containing the re-encrypted deck and a ZK proof.
/// Submit on-chain via `submit_shuffle`.
#[wasm_bindgen]
pub struct ShuffleMessage(InnerShuffleMessage);

/// A reveal message for a single card from a single player.
/// Submit on-chain via `submit_reveal`.
#[wasm_bindgen]
pub struct RevealMessage(InnerRevealMessage);

/// Collector for reveal messages. Feed all N reveals then unmask.
#[wasm_bindgen]
pub struct Reveals(Vec<InnerRevealMessage>);

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Generate a player keypair. `name` is the raw 32-byte AccountId.
#[wasm_bindgen]
pub fn generate_player(name: &[u8]) -> Result<PlayerData, JsError> {
    let (hello, keypair) = crate::keys::generate_player(name);
    Ok(PlayerData { hello, keypair })
}

/// Create a zero-masked deck from the first `count` static deck plaintexts.
#[wasm_bindgen]
pub fn zero_mask_deck(count: u32) -> Result<MaskedDeck, JsError> {
    let count = count as usize;
    if count > DECK.len() {
        return Err(JsError::new(&format!(
            "count {} exceeds max deck size {}",
            count,
            DECK.len()
        )));
    }
    let masked = cards_protocol::masking::zero_mask_cards(&DECK[..count]);
    Ok(MaskedDeck(masked))
}

/// Maximum supported deck size (200 for secp256k1).
#[wasm_bindgen]
pub fn max_deck_size() -> u32 {
    DECK.len() as u32
}

// ---------------------------------------------------------------------------
// PlayerData
// ---------------------------------------------------------------------------

#[wasm_bindgen]
impl PlayerData {
    /// Extract the public hello message.
    pub fn hello(&self) -> PlayerHello {
        PlayerHello(self.hello.clone())
    }

    /// Extract the secret keypair.
    pub fn keypair(&self) -> PlayerKeypair {
        PlayerKeypair(self.keypair.clone())
    }
}

// ---------------------------------------------------------------------------
// PlayerHello
// ---------------------------------------------------------------------------

#[wasm_bindgen]
impl PlayerHello {
    /// Serialize for on-chain submission (`register_player`).
    pub fn to_bytes(&self) -> Vec<u8> {
        ser(&self.0)
    }
}

// ---------------------------------------------------------------------------
// MaskedDeck
// ---------------------------------------------------------------------------

#[wasm_bindgen]
impl MaskedDeck {
    /// Deserialize from on-chain `CurrentDeck` storage.
    pub fn from_bytes(bytes: &[u8]) -> Result<MaskedDeck, JsError> {
        Ok(MaskedDeck(de(bytes)?))
    }

    /// Serialize for on-chain submission (`submit_masked_deck`).
    pub fn to_bytes(&self) -> Vec<u8> {
        ser(&self.0)
    }

    /// Number of cards in the deck.
    pub fn card_count(&self) -> u32 {
        self.0.len() as u32
    }

    /// Get a single card by index.
    pub fn get_card(&self, index: u32) -> Result<MaskedCard, JsError> {
        self.0
            .get(index as usize)
            .map(|c| MaskedCard(*c))
            .ok_or_else(|| {
                JsError::new(&format!(
                    "card index {} out of range {}",
                    index,
                    self.0.len()
                ))
            })
    }
}

// ---------------------------------------------------------------------------
// MaskedCard
// ---------------------------------------------------------------------------

#[wasm_bindgen]
impl MaskedCard {
    /// Produce a reveal message for this card using the player's secret keypair.
    pub fn prove_reveal(&self, keypair: &PlayerKeypair) -> RevealMessage {
        let msg = PARAMS.prove_single_reveal_token(
            &mut getrandom_or_panic::getrandom_or_panic(),
            &keypair.0,
            &self.0,
        );
        RevealMessage(msg)
    }
}

// ---------------------------------------------------------------------------
// AggregatedKeys
// ---------------------------------------------------------------------------

#[wasm_bindgen]
impl AggregatedKeys {
    /// Deserialize from on-chain `AggregateKeyData` storage.
    pub fn from_bytes(bytes: &[u8]) -> Result<AggregatedKeys, JsError> {
        Ok(AggregatedKeys(de(bytes)?))
    }

    /// Shuffle and re-mask the deck, producing a ZK proof.
    pub fn shuffle(&self, deck: &MaskedDeck) -> Result<ShuffleMessage, JsError> {
        let msg = self.0.shuffle_and_remask_(&deck.0).map_err(proto_err)?;
        Ok(ShuffleMessage(msg))
    }
}

// ---------------------------------------------------------------------------
// ShuffleMessage
// ---------------------------------------------------------------------------

#[wasm_bindgen]
impl ShuffleMessage {
    /// Serialize for on-chain submission (`submit_shuffle`).
    pub fn to_bytes(&self) -> Vec<u8> {
        ser(&self.0)
    }

    /// Extract the shuffled deck from this message.
    pub fn deck(&self) -> MaskedDeck {
        MaskedDeck(self.0.deck.clone())
    }
}

// ---------------------------------------------------------------------------
// RevealMessage
// ---------------------------------------------------------------------------

#[wasm_bindgen]
impl RevealMessage {
    /// Serialize for on-chain submission (`submit_reveal`).
    pub fn to_bytes(&self) -> Vec<u8> {
        ser(&self.0)
    }

    /// Deserialize a reveal message read from on-chain storage.
    pub fn from_bytes(bytes: &[u8]) -> Result<RevealMessage, JsError> {
        Ok(RevealMessage(de(bytes)?))
    }
}

// ---------------------------------------------------------------------------
// Reveals (collector)
// ---------------------------------------------------------------------------

#[wasm_bindgen]
impl Reveals {
    /// Create an empty reveal collector.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Reveals {
        Reveals(Vec::new())
    }

    /// Add a reveal message (clones internally — caller keeps their copy).
    pub fn add(&mut self, msg: &RevealMessage) {
        self.0.push(msg.0.clone());
    }

    /// Add a reveal message from serialized bytes.
    pub fn add_from_bytes(&mut self, bytes: &[u8]) -> Result<(), JsError> {
        self.0.push(de(bytes)?);
        Ok(())
    }

    /// Number of reveals collected so far.
    pub fn count(&self) -> u32 {
        self.0.len() as u32
    }

    /// Unmask the card using all collected reveals.
    /// Returns the deck position (use `cardType()` in TS to map to game meaning).
    pub fn unmask(&self, card: &MaskedCard) -> Result<u32, JsError> {
        let unmasked = PARAMS
            .unmask(&self.0, &card.0)
            .map_err(|e| JsError::new(&format!("unmask failed: {e:?}")))?;
        let position = deck_secp256k1::DECK_SECP256K1
            .decode(&unmasked.0)
            .ok_or_else(|| JsError::new("card not in deck"))?;
        Ok(position as u32)
    }
}
