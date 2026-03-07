
use wasm_bindgen::prelude::*;

use cards_protocol::error::CardProtocolError;
use cards_proofs::error::CryptoError;
use ark_serialize::SerializationError;

use crate::MaskedCard;

#[wasm_bindgen]
pub struct MaskedCards(pub(crate) Vec<MaskedCard>);

impl core::ops::Deref for MaskedCards {
    type Target = [MaskedCard];
    fn deref(&self) -> &Self::Target { self.0.as_slice()}
}
impl core::ops::DerefMut for MaskedCards {
    fn deref_mut(&mut self) -> &mut Self::Target { self.0.as_mut_slice()}    
}

#[wasm_bindgen]
pub fn zero_mask_deck() -> MaskedCards {
    MaskedCards(crate::zero_mask_deck())
}


#[wasm_bindgen(js_name="CardsError")]
#[repr(transparent)]
pub struct CardsErrorWasm(#[wasm_bindgen(readonly)] pub(crate) String);

#[wasm_bindgen]
impl CardsErrorWasm {
    pub fn as_js_error(&self) -> JsError {
        JsError::new(&self.0)
    }
}

impl From<CardProtocolError> for CardsErrorWasm {
    fn from(err: CardProtocolError) -> Self {
        CardsErrorWasm(err.to_string())
    }
}

impl From<CryptoError> for CardsErrorWasm {
    fn from(err: CryptoError) -> Self {
        CardsErrorWasm(err.to_string())
    }
}

impl From<SerializationError> for CardsErrorWasm {
    fn from(err: SerializationError) -> Self {
        CardsErrorWasm(err.to_string())
    }
}

impl<'a> From<&'a str> for CardsErrorWasm {
    fn from(err: &'a str) -> Self {
        CardsErrorWasm(err.to_string())
    }
}

pub type ResultWasm<T> = Result<T,CardsErrorWasm>;


/// Reimplements cards_protocol::reveal::card_position, but using wasm weaker types
// TODO:  Use CardsErrorWarm not Option<..>?  Or can zero be ignored here?
// TODO:  Card index position vs point bytes?  Use deck being sorted?
#[cfg(feature="wasm")]
pub fn card_position(crd: &super::UnmaskedCard) -> ResultWasm<usize> {
    use ark_std::Zero;
    if crd.is_zero() { return Ok(usize::MAX); }
    Ok(super::DECK.iter().position(|c| c==crd)
        .ok_or(CardProtocolError::UnrecognizedCard)?)
}
