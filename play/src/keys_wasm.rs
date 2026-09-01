
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

#[wasm_bindgen(js_class = "PlayerKeypair")]
impl PlayerKeypairWasm{
    #[wasm_bindgen(constructor)]
    pub fn player_keygen() -> PlayerKeypairWasm {
        PlayerKeypairWasm(keys::player_keygen())
    }

    /// Include any delegating public key in `player_public_info` for back certification
    #[cfg(feature="prover")]
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

    /// Produce a `RevealMessage` (reveal token + ZK proof) for a single masked card.
    #[cfg(feature="prover")]
    pub fn prove_reveal(
        &self, masked_card_bytes: &[u8],
    ) -> ResultWasm<Vec<u8>> {
        let masked_card = crate::MaskedCard::deserialize(masked_card_bytes)?;
        let reveal_msg = crate::PARAMS.prove_single_reveal_token(
            &mut getrandom_or_panic(), &self.0, &masked_card,
        );
        Ok(reveal_msg.serialize_to_vec()?)
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
    /// Build AggregatedPublicKeys from player hellos.
    /// `hellos_and_names` is a flat buffer: [num_players: u32 LE, then for each:
    ///   hello_len: u32 LE, hello_bytes, name_len: u32 LE, name_bytes]
    #[wasm_bindgen(js_name="buildFromHellos")]
    pub fn wasm_build_from_hellos(hellos_and_names: &[u8]) -> wasm::ResultWasm<AggregatedPublicKeys> {
        let mut cursor = 0usize;
        if hellos_and_names.len() < 4 { return Err("too short".into()); }
        let num = u32::from_le_bytes([
            hellos_and_names[0], hellos_and_names[1],
            hellos_and_names[2], hellos_and_names[3],
        ]) as usize;
        cursor += 4;

        let mut players: Vec<(&[u8], &[u8])> = Vec::with_capacity(num);
        for _ in 0..num {
            if hellos_and_names.len() < cursor + 4 { return Err("bad format".into()); }
            let hello_len = u32::from_le_bytes([
                hellos_and_names[cursor], hellos_and_names[cursor+1],
                hellos_and_names[cursor+2], hellos_and_names[cursor+3],
            ]) as usize;
            cursor += 4;
            if hellos_and_names.len() < cursor + hello_len { return Err("bad format".into()); }
            let hello = &hellos_and_names[cursor..cursor + hello_len];
            cursor += hello_len;

            if hellos_and_names.len() < cursor + 4 { return Err("bad format".into()); }
            let name_len = u32::from_le_bytes([
                hellos_and_names[cursor], hellos_and_names[cursor+1],
                hellos_and_names[cursor+2], hellos_and_names[cursor+3],
            ]) as usize;
            cursor += 4;
            if hellos_and_names.len() < cursor + name_len { return Err("bad format".into()); }
            let name = &hellos_and_names[cursor..cursor + name_len];
            cursor += name_len;

            players.push((hello, name));
        }
        Ok(keys::build_aggregate_keys(&players)?)
    }

    #[wasm_bindgen(js_name="deserialize")]
    pub fn wasm_deserialize(selfy: &[u8]) -> wasm::ResultWasm<AggregatedPublicKeys> {
        Ok(AggregatedPublicKeys::deserialize(selfy) ?)
    }

    #[wasm_bindgen(js_name="serialize")]
    pub fn wasm_serialize(&self) -> Vec<u8> {
        self.serialize_to_vec().unwrap()
    }

    #[cfg(feature="prover")]
    #[wasm_bindgen(js_name="shuffle_and_remask")]
    pub fn wasm_shuffle_and_remask(
        &self, sk: &PlayerKeypairWasm, deck: &MaskedCards,
    ) -> ResultWasm<Vec<u8> /*ShuffleMessage*/> {
        let shuffle_message = self.shuffle_and_remask(&sk.0, deck.0.as_slice())?;
        // We'd ideally propogate the shuffle error above but wasm-bindgen
        // makes this hard.  Afaik it only occurs because of some incorrect
        // lengths in the parameters and SRS, or some internal error that
        // passes wrong lengths. 
        Ok(shuffle_message.serialize_to_vec()?)
    }

    #[wasm_bindgen(js_name="verify_shuffle")]
    pub fn wasm_verify_shuffle(
        &self, idx: usize, original_deck: &MaskedCards, shuffle_message: &[u8],
    ) -> ResultWasm<MaskedCards> {
        let shuffle_message = ShuffleMessage::deserialize(shuffle_message) ?;
        let (pk,shuffled_deck) = self.0.verify_shuffle(original_deck.0.as_slice(),&shuffle_message) ?;
        if self.0.players().get(idx) != Some(pk) {
            return Err("Incorrect player signed valid shuffle".into());
        }
        Ok(MaskedCards(shuffled_deck.to_owned()))
    }

    /// Create an `AccumulateReveals` for a single masked card.
    /// Feed `RevealMessage`s into it via `add_reveal_wasm`, then call `completed_position`.
    #[wasm_bindgen(js_name="accumulate_reveals")]
    pub fn wasm_accumulate_reveals(
        &self, masked_card_bytes: &[u8],
    ) -> ResultWasm<crate::AccumulateReveals> {
        let masked_card = crate::MaskedCard::deserialize(masked_card_bytes)?;
        Ok(crate::AccumulateReveals(self.0.accumulate_reveals(masked_card)))
    }
}
