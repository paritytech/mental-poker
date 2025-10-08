use crate::*;

pub trait AggregatedPublicKeysExt {
    fn shuffle_and_remask_(&self, deck: &[MaskedCard])
        -> Result<ShuffleMessage, CardProtocolError>;
}

impl AggregatedPublicKeysExt for AggregatedPublicKeys {
    fn shuffle_and_remask_(
        &self,deck: &[MaskedCard],
    ) -> Result<ShuffleMessage, CardProtocolError> {
        self.shuffle_and_remask(&mut getrandom_or_panic::getrandom_or_panic(), deck)
    }
}
