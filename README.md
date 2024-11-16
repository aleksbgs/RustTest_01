Discrete Logarithm Proof (DLog Proof) in Rust
This Rust project implements a zero-knowledge proof system to demonstrate knowledge of a private key corresponding to a public key without revealing the private key. The system uses the discrete logarithm problem on elliptic curves as its basis.

Features
Generate random scalars for elliptic curve operations.
Prove knowledge of private key (DLogProof) using a random challenge-response mechanism.
Verify the proof using elliptic curve arithmetic.
Elliptic Curve Cryptography (ECC) with SHA-256 hashing for deterministic proof generation.
Comprehensive unit tests to ensure the correctness of the implementation.
Dependencies
This project uses the following Rust crates:

sha2: For SHA-256 hashing.
k256: For elliptic curve cryptography using the secp256k1 curve.
rand_core: For generating secure random numbers.
Installation
To use or modify this project:

Clone this repository:
bash
Copy code
git clone https://github.com/aleksbgs/RustTest_01.git
cd where you install
Install the Rust toolchain if not already installed:
bash
Copy code
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
Build the project:
bash
Copy code
cargo build

run tests
cargo test

How It Works
Proof Generation
A proof is generated to show that the prover knows a private key (x) without revealing it.


Fork the repository.
Submit issues for bugs or feature requests.
Create pull requests with improvements.
License
This project is licensed under the MIT License.

Acknowledgments
Special thanks to the creators of the k256 and sha2 crates for their robust cryptographic libraries.
