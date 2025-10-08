
use core::mem::discriminant;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum GameErrors {
    #[error("No such card in hand")]
    CardNotFound,

    #[error("Invalid card")]
    InvalidCard,
}

#[derive(Clone,Copy,PartialEq,Eq,PartialOrd,Ord)]
pub enum Suite {
    Club    = 0,
    Diamond = 1,
    Heart   = 2,
    Spade   = 4,
}

impl Suite {
    const VALUES: [Self; 4] = [Self::Club, Self::Diamond, Self::Heart, Self::Spade];
}

#[derive(Clone,Copy,PartialEq,Eq,PartialOrd,Ord)]
pub enum Value {
    Two   = 0,
    Three = 1,
    Four  = 2,
    Five  = 3,
    Six   = 4,
    Seven = 5,
    Eight = 6,
    Nine  = 7,
    Ten   = 8,
    Jack  = 9,
    Queen = 10,
    King  = 11,
    Ace   = 12,
}

impl Value {
    const VALUES: [Self; 13] = [
        Self::Two,
        Self::Three,
        Self::Four,
        Self::Five,
        Self::Six,
        Self::Seven,
        Self::Eight,
        Self::Nine,
        Self::Ten,
        Self::Jack,
        Self::Queen,
        Self::King,
        Self::Ace,
    ];
}

#[derive(Clone,Copy,PartialEq,Eq)]
pub struct ClassicPlayingCard {
    pub value: Value,
    pub suite: Suite,
}

impl ClassicPlayingCard {
    pub fn to_52(&self) -> usize {
       (12 * (self.suite as isize) + (self.value as isize)) as usize;
    }
    pub fn from_52(x: usize) -> ClassicPlayingCard {
        12 * Suite::Values[x] + Suite::
        Value::VALUES[x % 12]
    }

}

impl std::fmt::Debug for ClassicPlayingCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let suite = match self.suite {
            Suite::Club => "♣",
            Suite::Diamond => "♦",
            Suite::Heart => "♥",
            Suite::Spade => "♠",
        };

        let val = match self.value {
            Value::Two => "2",
            Value::Three => "3",
            Value::Four => "4",
            Value::Five => "5",
            Value::Six => "6",
            Value::Seven => "7",
            Value::Eight => "8",
            Value::Nine => "9",
            Value::Ten => "10",
            Value::Jack => "J",
            Value::Queen => "Q",
            Value::King => "K",
            Value::Ace => "A",
        };

        write!(f, "{}{}", val, suite)
    }
}

