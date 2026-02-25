#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

use ark_std::{
    // borrow::Borrow,
    boxed::Box,
    io::{self, Write}, // Read
    rand::Rng,
    UniformRand,
    // ops::Deref,
    vec::Vec,
};

use ark_ec::AffineRepr;
use ark_serialize::{CanonicalSerialize, Compress, SerializationError};

// #[cfg(feature = "cards-proofs")]
// use cards_proofs::homomorphic_encryption::el_gamal;

#[cfg(feature = "cards-proofs")]
pub type ElGamalPlaintext<A> =
    cards_proofs::homomorphic_encryption::el_gamal::Plaintext<<A as AffineRepr>::Group>;

/// Generic hash-to-curve 
///
/// Use [IETF RFC9380](https://datatracker.ietf.org/doc/rfc9380/)
/// or similar for your curve if you need a faster hash-to-curve.
pub fn exrtact_card<A: AffineRepr, R: Rng + ?Sized>(rng: &mut R) -> A {
    UniformRand::rand(rng)
}

// #[cfg(feature = "cards-proofs")]
// pub fn create_card<A: AffineRepr>(seed: &[u8; 32]) -> ElGamalPlaintext<A> {
//     let mut rng = ;
//     cards_proofs::homomorphic_encryption::el_gamal::Plaintext(exrtact_card(&mut rng))
// }

#[cfg(feature = "cards-proofs")]
pub const fn cast_deck<A: AffineRepr>(deck: &[A]) -> &[ElGamalPlaintext<A>] {
    unsafe { core::mem::transmute::<&[A], &[ElGamalPlaintext<A>]>(deck) }
}

pub trait Deck {
    type C;
    fn encode(&self, card_index: usize) -> Option<&Self::C>;
    fn decode(&self, point: &Self::C) -> Option<usize>;
}

#[derive(Debug)]
#[repr(transparent)]
pub struct SortedDeck<A: AffineRepr>(pub [A]);

// fn xy_key<A: AffineRepr>(p: &A) -> Option<(A::BaseField, A::BaseField)> { p.xy() }

fn serialize_key<A: AffineRepr>(p: &A) -> [u8; 100] {
    let mut buf = [0u8; 100];
    {
        let mut cursor = ark_std::io::Cursor::new(&mut buf[..]);
        p.serialize_compressed(&mut cursor)
            .expect("At present nobody uses elliptic curves bigger than 100 bytes.");
    }
    buf
}

impl<A: AffineRepr> SortedDeck<A> {
    pub const fn from_slice<'a>(s: &'a [A]) -> &'a SortedDeck<A> {
        unsafe { core::mem::transmute::<&[A], &SortedDeck<A>>(s) }
    }

    pub fn from_vec<'a>(v: Vec<A>) -> Box<SortedDeck<A>> {
        let v = v.into_boxed_slice();
        unsafe { core::mem::transmute::<Box<[A]>, Box<SortedDeck<A>>>(v) }
    }

    pub fn from_rng<R: Rng + ?Sized>(n: u32, rng: &mut R) -> Box<SortedDeck<A>> {
        let mut v: Vec<A> = (0..n).map(|_| exrtact_card(rng)).collect();
        v.sort_by_key(serialize_key);
        SortedDeck::from_vec(v)
    }

    #[cfg(feature = "std")]
    pub fn to_code<W: Write>(&self, w: &mut W, name: &str) -> io::Result<()> {
        // let affine = affine.unwrap_or(std::any::type_name::<A>());
        let affine = "Affine";
        // writeln!(w, "use ark_ff::MontFp;")?;
        writeln!(w, "pub static {}: &'static [{}; {}] = &[", name, affine, self.0.len())?;
        for p in &self.0 {
            write_point(w, affine, p)?;
        }
        writeln!(w, "];")
    }
}

#[cfg(feature = "std")]
pub fn write_point<W: Write>(w: &mut W, affine: &str, p: &impl AffineRepr) -> io::Result<()> {
    if let Some((x, y)) = p.xy() {
        writeln!(w, "{}::new_unchecked(MontFp!(\"{:#?}\"), MontFp!(\"{:#?}\")),", affine, x, y)
    } else {
        writeln!(w, "{}::zero(),", affine)
    }
}

impl<A: AffineRepr> Deck for SortedDeck<A> {
    type C = A;
    fn encode(&self, card_index: usize) -> Option<&A> {
        self.0.get(card_index as usize)
    }
    fn decode(&self, point: &A) -> Option<usize> {
        self.0.binary_search_by_key(&serialize_key(point), serialize_key).ok()
    }
}

/*
impl<A: AffineRepr> Deref for SortedDeck<A> {
    type Target = [A];
    fn deref(&self) -> &[A] {
        &self.0
    }
}

impl<A: AffineRepr> Borrow<[A]> for SortedDeck<A> {
    fn borrow(&self) -> &[A] {
        self.0.borrow()
    }
}

impl<A: AffineRepr> AsRef<[A]> for SortedDeck<A> {
    fn as_ref(&self) -> &[A] {
        self.0.as_ref()
    }
}

#[cfg(feature = "cards-proofs")]
impl<A: AffineRepr> AsRef<[ElGamalPlaintext<A>]> for SortedDeck<A> {
    fn as_ref(&self) -> &[ElGamalPlaintext<A>] {
        cast_deck( self.0.as_ref() )
    }
}
*/

impl<A: AffineRepr> SortedDeck<A> {
    pub fn as_affine(&self) -> &[A] {
        self.0.as_ref()
    }

    #[cfg(feature = "cards-proofs")]
    pub fn as_el_gamal(&self) -> &[ElGamalPlaintext<A>] {
        cast_deck(self.0.as_ref())
    }
}

impl<'a, A: AffineRepr> IntoIterator for &'a SortedDeck<A> {
    type Item = &'a A;
    type IntoIter = core::slice::Iter<'a, A>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<A: AffineRepr> CanonicalSerialize for SortedDeck<A> {
    #[inline]
    fn serialize_with_mode<W: Write>(
        &self, mut writer: W, compress: Compress,
    ) -> Result<(), SerializationError> {
        self.0.serialize_with_mode(&mut writer, compress)
    }

    #[inline]
    fn serialized_size(&self, compress: Compress) -> usize {
        self.0.serialized_size(compress)
    }
}
