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
cd dlog-proof-rust
Install the Rust toolchain if not already installed:
bash
Copy code
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
Build the project:
bash
Copy code
cargo build
How It Works
Proof Generation
A proof is generated to show that the prover knows a private key (x) without revealing it.
The proof consists of:

A commitment point (t).
A proof scalar (s).
Proof Verification
The verifier checks that:

The proof satisfies the challenge-response relationship.
The operations align with the discrete logarithm problem constraints.
Usage
Run the Code
Execute the main program:

bash
Copy code
cargo run
Expected output:

text
Copy code
Proof computation time: <time in ms> ms
t.x: <x-coordinate of the commitment point>
t.y: <y-coordinate of the commitment point>
Verify computation time: <time in ms> ms
DLOG proof is correct
Run Unit Tests
Run the included unit tests to ensure the implementation is correct:

bash
Copy code
cargo test
Expected output:

text
Copy code
running 6 tests
test tests::test_generate_random_scalar ... ok
test tests::test_compute_hash_consistency ... ok
test tests::test_generate_proof_and_verify_valid ... ok
test tests::test_generate_proof_and_verify_invalid ... ok
test tests::test_generate_proof_and_verify_different_keys ... ok
test tests::test_proof_consistency_for_same_inputs ... ok
Code Overview
1. generate_random_scalar
Generates a random scalar value using a secure random number generator.

2. DLogProof Struct
Represents the proof with two components:

commitment_point: An elliptic curve point.
proof_scalar: A scalar derived from the challenge and the private key.
3. compute_hash
Computes a SHA-256 hash over elliptic curve points and additional metadata (session ID, party ID).

4. generate_proof
Creates a proof by:

Randomly generating a commitment scalar.
Computing the challenge hash.
Combining the commitment scalar with the private key and challenge.
5. verify_proof
Verifies the proof by recomputing the challenge and checking the consistency of the elliptic curve operations.

Example
Here’s an example of generating and verifying a DLog proof:

rust
Copy code
fn main() {
    let session_id = "session1";
    let party_id = 42;

    // Generate a private scalar (private key)
    let private_key = generate_random_scalar();

    // Use the base generator of the elliptic curve
    let base_curve_point = ProjectivePoint::GENERATOR;

    // Compute the public key (base_point * private_key)
    let public_key = base_curve_point * private_key;

    // Generate the proof
    let proof = DLogProof::generate_proof(session_id, party_id, private_key, base_curve_point);

    // Verify the proof
    let is_valid = proof.verify_proof(session_id, party_id, public_key, base_curve_point);

    // Output results
    if is_valid {
        println!("Proof verified successfully!");
    } else {
        println!("Proof verification failed!");
    }
}
Key Security Considerations
Always use secure random number generators (e.g., OsRng).
Ensure all hashing is deterministic to avoid side-channel attacks.
Never reuse the same private key for different proofs in high-security applications.
Contributing
Contributions are welcome! Feel free to:

Fork the repository.
Submit issues for bugs or feature requests.
Create pull requests with improvements.
License
This project is licensed under the MIT License.

Acknowledgments
Special thanks to the creators of the k256 and sha2 crates for their robust cryptographic libraries.
