# Mental Poker

A mental poker protocol based upon Bayer-Groth shuffles of ElGamal ciphertexts over an elliptic curve

## Background

We fork and build upon the [mental poker library](https://hackmd.io/@nmohnblatt/SJKJfVqzq) by Kobi Gurkan and Nicolas Mohnblatt, which still provides the shuffles code used here.

["Mental Poker"](https://en.wikipedia.org/wiki/Mental_poker) was first formulated by [A. Shamir, R. Rivest, and L. Adleman in 1979](https://apps.dtic.mil/dtic/tr/fulltext/u2/a066331.pdf), and dramatically improved by [A. Barnett and N. Smart in 2003](https://www.semanticscholar.org/paper/Mental-Poker-Revisited-Barnett-Smart/8aaa1245c5876c78564c3f2df36ca615686d1402). 

Jens Groth and Stephanie Bayer devised an asymptotically far more efficent shuffle protocol in ["Efficient zero-knowledge argument for correctness of a shuffle."](https://dl.acm.org/doi/10.1007/978-3-642-29011-4_17) in 2012, then used in the [proof-toolbox](https://github.com/geometryxyz/proof-toolbox/) and [mental-poker](https://github.com/geometryxyz/mental-poker/) crates by Gurkan and Mohnblatt.

## Running the example

An example showing how to encode, hide, shuffle and distribute cards is provided under [`mental-poker/barnett-smart-card-protocol/examples/round.rs`](https://github.com/geometryresearch/mental-poker/blob/main/barnett-smart-card-protocol/examples/round.rs). Run the example by running:

```
cargo run --example round
```

## License

&copy; 2025 [Jeffrey Burdges](https://github.com/burdges/).
&copy; 2022 [Geometry](https://geometryresearch.xyz).

Through 2025, this crate is licensed under either of

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE))
- [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT))

at your option.

The [SPDX](https://spdx.dev) license identifier for this crate is `MIT OR Apache-2.0`.
