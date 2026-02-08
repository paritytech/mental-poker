use cards_protocol::IntoTranscript;

use crate::*;

pub fn generate_player(
    player_public_info: impl IntoTranscript,
) -> (PlayerHello, PlayerKeypair) {
    PARAMS.generate_player(&mut getrandom_or_panic(),player_public_info)
}

pub fn verify_player(
    pk: &PlayerHello,
    player_public_info: impl IntoTranscript,
) -> Result<(), CardProtocolError> {
    Ok(PARAMS.verify_player(pk,player_public_info)?)
}

pub trait AggregatedPublicKeysExt {
    /// Shuffle cards and produce proof using system randomness
    ///
    /// Verified using `verify_shuffle`
    fn shuffle_and_remask_(&self, deck: &[MaskedCard])
        -> Result<ShuffleMessage, CardProtocolError>;
    
    /// verify_merged_reveals
    fn verify_quit<'a,'b>(
        &mut self,
        reveals: &'a RevealsMerged,
        masked_cards: impl IntoIterator<Item=&'b MaskedCard>,
    ) -> Result<&'a [RevealToken], CardProtocolError>;  // Not CryptoError?
}

impl AggregatedPublicKeysExt for AggregatedPublicKeys {
    fn shuffle_and_remask_(
        &self,deck: &[MaskedCard],
    ) -> Result<ShuffleMessage, CardProtocolError> {
        self.shuffle_and_remask(&mut getrandom_or_panic(), deck)
    }

    fn verify_quit<'a,'b>(
        &mut self,
        reveals: &'a RevealsMerged,
        masked_cards: impl IntoIterator<Item=&'b MaskedCard>,
    ) -> Result<&'a [RevealToken], CardProtocolError> {  // Not CryptoError?
        let idx = self.player_index(&reveals.pk)?;
        verify_merged_reveals(reveals,masked_cards)
        .map(|r| { let _ = self.remove(idx); r })
    }
}

pub fn prove_merged_reveals<'a>(
    key: &PlayerKeypair,
    masked_cards: impl IntoIterator<Item=&'a MaskedCard>,
) -> RevealsMerged {
    crate::PARAMS.prove_merged_reveals(&mut getrandom_or_panic(), key, masked_cards)
}

pub fn verify_merged_reveals<'a,'b>(
    reveals: &'a RevealsMerged,
    masked_cards: impl IntoIterator<Item=&'b MaskedCard>,
) -> Result<&'a [RevealToken], CardProtocolError> {  // Not CryptoError?
    Ok(crate::PARAMS.verify_merged_reveals(reveals, masked_cards)?)
}


// wasm bidgen TODO:
//
// generate_player
// verify_player
// prove_merged_reveals
// verify_merged_reveals
//
// On AggregatedPublicKeys::
// verify_n_add
// shuffle_and_remask_
// verify_shuffle
// prove_merged_reveals
// verify_quit
//
//
//