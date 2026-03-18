
use crate::{*, wasm::{MaskedCards,ResultWasm}};

use ez_serialize::{EzSerialize,EzDeserialize};

// use wasm_bindgen::prelude::*;


#[wasm_bindgen(js_name="PlayerKeypair")]
pub struct PlayerKeypairWasm(pub(crate) PlayerKeypair);

impl core::ops::Deref for PlayerKeypairWasm {
    type Target = PlayerKeypair;
    fn deref(&self) -> &Self::Target { &self.0}
}
impl core::ops::DerefMut for PlayerKeypairWasm {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0}
}

// We cannot return a Vec<u8> plus another typeunder wasm-bindgen so no generate_player

#[wasm_bindgen]
impl PlayerKeypairWasm{
    #[wasm_bindgen(constructor)]
    pub fn player_keygen() -> PlayerKeypairWasm {
        PlayerKeypairWasm(keys::player_keygen())
    }

    /// Include any delegating public key in `player_public_info` for back certification
    pub fn prove_player(
        &self, player_public_info: &[u8],
    ) -> Vec<u8> /* PlayerHello */ {
        keys::prove_player(self,player_public_info).serialize_to_vec().unwrap()
    }

    #[wasm_bindgen(js_name="deserialize")]
    pub fn wasm_deserialize(selfy: &[u8]) -> wasm::ResultWasm<PlayerKeypairWasm> {
        Ok(PlayerKeypairWasm(keys::player_deserialize(selfy) ?))
    }

    /// Warning: Never send this off the machine
    #[wasm_bindgen(js_name="serialize")]
    pub fn wasm_serialize(&self) -> Vec<u8> {
        self.0.serialize_to_vec().unwrap()
    }
}

/// Assumes correct format and returns empty string if not.
#[wasm_bindgen]
pub fn player_public(
    pk: &[u8], /* PlayerHello */
) -> Vec<u8> {
    if let Ok(pk) = PlayerHello::deserialize(pk) {
        pk.as_affine().serialize_to_vec().unwrap()
    } else { Vec::new() }
}

#[wasm_bindgen]
pub fn verify_player(
    pk: &[u8], /* PlayerHello */
    player_public_info: &[u8],
) -> ResultWasm<Vec<u8>> {
    let pk = PlayerHello::deserialize(pk)?;
    keys::verify_player(&pk,player_public_info)?;
    Ok(pk.as_affine().serialize_to_vec()?)
}


#[wasm_bindgen]
impl AggregatedPublicKeys {
    #[wasm_bindgen(js_name="deserialize")]
    pub fn wasm_deserialize(selfy: &[u8]) -> wasm::ResultWasm<AggregatedPublicKeys> {
        Ok(AggregatedPublicKeys::deserialize(selfy) ?)
    }

    #[wasm_bindgen(js_name="serialize")]
    pub fn wasm_serialize(&self) -> Vec<u8> {
        self.serialize_to_vec().unwrap()
    }

    #[wasm_bindgen(js_name="shuffle_and_remask")]
    pub fn wasm_shuffle_and_remask(
        &self, deck: &MaskedCards,
    ) -> ResultWasm<Vec<u8> /*ShuffleMessage*/> {
        let shuffle_message = self.shuffle_and_remask(deck.0.as_slice())?;
        // We'd ideally propogate the shuffle error above but wasm-bindgen
        // makes this hard.  Afaik it only occurs because of some incorrect
        // lengths in the parameters and SRS, or some internal error that
        // passes wrong lengths. 
        Ok(shuffle_message.serialize_to_vec()?)
    }

    #[wasm_bindgen(js_name="verify_shuffle")]
    pub fn wasm_verify_shuffle(
        &self, original_deck: &MaskedCards, shuffle_message: &[u8], 
    ) -> ResultWasm<MaskedCards> {
        let shuffle_message = ShuffleMessage::deserialize(shuffle_message) ?;
        let shuffled_deck = self.0.verify_shuffle(original_deck.0.as_slice(),&shuffle_message) ?;
        Ok(MaskedCards(shuffled_deck.to_owned()))
    }
}
