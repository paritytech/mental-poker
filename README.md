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


Since 2025, this project is licensed under the [GNU Affero General Public License version 3](https://www.gnu.org/licenses/agpl.html) ([`LICENSE-AGPL-v3.0.txt`](LICENSE-AGPL-v3.0)) as published by the Free Software Foundation.

Ergo, the [SPDX](https://spdx.dev) license identifier for this project is `AGPL-3.0-or-later`.

All commits from 2024 or earlier are &copy; 2022 [Geometry](https://geometryresearch.xyz), who licenses them under either of the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](proofs/LICENSE-APACHE)), or the [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](proofs/LICENSE-MIT)), at your option.  We strongly suggest you clone from [github.com/geometryxyz/mental-poker](https://github.com/geometryxyz/mental-poker/) if you want their original `MIT OR Apache-2.0` licensed version.

<!-- A series of posts explaining the protocol and our approach to implementing it are available in the [Geometry Notebook](https://geometryresearch.xyz/notebook). [Part 1](https://geometryresearch.xyz/notebook/mental-poker-in-the-age-of-snarks-part-1) covers the protocol and primitives from a high level, [Part 2](https://geometryresearch.xyz/notebook/mental-poker-in-the-age-of-snarks-part-2) goes into some of the math. -->
