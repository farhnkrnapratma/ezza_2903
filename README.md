# ezza-2903

A secure and simple CLI tool for encrypting and decrypting files using the `XChaCha20Poly1305` AEAD encryption algorithm.

## Features

- Secure symmetric encryption with XChaCha20Poly1305
- Random key generation
- Safe base64 encoding and decoding
- Command-line interface using `clap`
- Built-in nonce handling for every encryption

---

## Installation

Clone this repository and build the project using [Cargo](https://doc.rust-lang.org/cargo/):

```bash
git clone https://github.com/farhnkrnapratma/ezza-2903.git
cd ezza-2903
cargo build --release
