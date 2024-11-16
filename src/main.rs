use std::time::Instant;
use sha2::{Digest, Sha256}; // Importing SHA-256 hashing function and its Digest trait.
use k256::{elliptic_curve::sec1::ToEncodedPoint, Scalar, ProjectivePoint}; // Importing Scalar, ProjectivePoint, and point encoding utilities from k256.
use rand_core::OsRng; // Importing a secure random number generator.
use k256::elliptic_curve::{Field, PrimeField}; // Importing elliptic curve Field and PrimeField traits for arithmetic operations.


// Function to generate a random scalar using a secure RNG.
fn generate_random_scalar() -> Scalar {
    Scalar::random(&mut OsRng) // Generate a random scalar value.
}

// Struct representing the Discrete Logarithm (DLog) proof.
struct DLogProof {
    t: ProjectivePoint, // Commitment point.
    s: Scalar,          // Scalar value for the proof.
}

impl DLogProof {
    // Hash elliptic curve points using SHA-256.
    fn hash_points(sid: &str, pid: u64, points: &[ProjectivePoint]) -> Scalar {
        let mut hasher = Sha256::new(); // Create a new SHA-256 hasher.
        hasher.update(sid.as_bytes()); // Add the session ID to the hash.
        hasher.update(&pid.to_le_bytes()); // Add the party ID to the hash.

        for point in points {
            let affine = point.to_affine(); // Convert the point to affine coordinates.
            let encoded = affine.to_encoded_point(false); // Encode the affine point.
            hasher.update(encoded.as_bytes()); // Add the encoded point to the hash.
        }

        let digest = hasher.finalize(); // Finalize the hash computation.
        let bytes: [u8; 32] = digest.as_slice().try_into().expect("Digest output is not 32 bytes"); // Ensure the hash is 32 bytes.
        let field_bytes = k256::FieldBytes::from(bytes); // Convert hash to FieldBytes.
        Scalar::from_repr(field_bytes).unwrap_or_else(|| Scalar::ONE) // Convert FieldBytes to Scalar or use ONE as a fallback.
    }

    // Generate a DLog proof.
    fn prove(sid: &str, pid: u64, x: Scalar, base_point: ProjectivePoint) -> DLogProof {
        let r = generate_random_scalar(); // Generate a random scalar.
        let t = base_point * r; // Compute the commitment point.
        let y = base_point * x; // Compute the public key.
        let c = DLogProof::hash_points(sid, pid, &[base_point, y, t]); // Compute the hash challenge.
        let s = r + c * x; // Compute the proof scalar.
        DLogProof { t, s } // Return the proof.
    }

    // Verify a DLog proof.
    fn verify(&self, sid: &str, pid: u64, y: ProjectivePoint, base_point: ProjectivePoint) -> bool {
        let c = DLogProof::hash_points(sid, pid, &[base_point, y, self.t]); // Recompute the hash challenge.
        let lhs = base_point * self.s; // Compute the left-hand side: g^s.
        let rhs = self.t + y * c; // Compute the right-hand side: t + y^c.
        lhs == rhs // Check if both sides are equal.
    }
}

fn main() {
    let sid = "sid"; // Define the session ID.
    let pid = 1; // Define the party ID.

    let x = generate_random_scalar(); // Generate a private scalar.
    let base_point = ProjectivePoint::GENERATOR; // Use the curve's base point.
    let y = base_point * x; // Compute the public key.

    let start_proof = Instant::now(); // Start timing the proof generation.
    let dlog_proof = DLogProof::prove(sid, pid, x, base_point); // Generate the proof.
    let proof_time = start_proof.elapsed().as_millis(); // Measure the time taken.
    println!("Proof computation time: {} ms", proof_time); // Print the proof generation time.

    let affine_t = dlog_proof.t.to_affine(); // Convert the commitment point to affine coordinates.
    let encoded_point = affine_t.to_encoded_point(false); // Encode the affine point.
    let x_bytes = encoded_point.x().expect("x-coordinate missing"); // Extract the x-coordinate.
    let y_bytes = encoded_point.y().expect("y-coordinate missing"); // Extract the y-coordinate.

    println!("t.x: {:?}", x_bytes); // Print the x-coordinate of the commitment point.
    println!("t.y: {:?}", y_bytes); // Print the y-coordinate of the commitment point.

    let start_verify = Instant::now(); // Start timing the verification.
    let result = dlog_proof.verify(sid, pid, y, base_point); // Verify the proof.
    let verify_time = start_verify.elapsed().as_millis(); // Measure the time taken.
    println!("Verify computation time: {} ms", verify_time); // Print the verification time.

    if result {
        println!("DLOG proof is correct"); // Print success message if proof is valid.
    } else {
        println!("DLOG proof is not correct"); // Print failure message if proof is invalid.
    }
}
#[cfg(test)] // Ensure these tests are only compiled during testing.
mod tests {
    use super::*; // Import everything from the main module.

    #[test]
    fn test_generate_random_scalar() {
        // Test if random scalar generation works and produces different values.
        let scalar1 = generate_random_scalar();
        let scalar2 = generate_random_scalar();
        assert!(scalar1 != scalar2, "Random scalars should not be equal");
    }

    #[test]
    fn test_hash_points() {
        // Test if hash_points produces consistent results for the same input.
        let sid = "test_sid";
        let pid = 1;
        let base_point = ProjectivePoint::GENERATOR;
        let random_point = base_point * generate_random_scalar();

        let hash1 = DLogProof::hash_points(sid, pid, &[base_point, random_point]);
        let hash2 = DLogProof::hash_points(sid, pid, &[base_point, random_point]);

        assert_eq!(hash1, hash2, "Hashes for the same input should be equal");

        // Test if changing input changes the hash.
        let different_point = base_point * generate_random_scalar();
        let different_hash = DLogProof::hash_points(sid, pid, &[base_point, different_point]);
        assert_ne!(hash1, different_hash, "Hashes for different inputs should not be equal");
    }

    #[test]
    fn test_prove_and_verify_valid_proof() {
        // Test if a valid proof passes verification.
        let sid = "test_sid";
        let pid = 1;
        let x = generate_random_scalar(); // Generate private key.
        let base_point = ProjectivePoint::GENERATOR;
        let y = base_point * x; // Compute public key.

        let proof = DLogProof::prove(sid, pid, x, base_point);
        let result = proof.verify(sid, pid, y, base_point);

        assert!(result, "Verification should succeed for a valid proof");
    }

    #[test]
    fn test_prove_and_verify_invalid_proof() {
        // Test if an invalid proof fails verification.
        let sid = "test_sid";
        let pid = 1;
        let x = generate_random_scalar();
        let base_point = ProjectivePoint::GENERATOR;
        let y = base_point * x;

        let proof = DLogProof::prove(sid, pid, x, base_point);

        // Tamper with the proof (modify s).
        let tampered_proof = DLogProof {
            t: proof.t,
            s: proof.s + Scalar::ONE,
        };

        let result = tampered_proof.verify(sid, pid, y, base_point);

        assert!(!result, "Verification should fail for a tampered proof");
    }

    #[test]
    fn test_prove_and_verify_different_keys() {
        // Test if verification fails for different keys.
        let sid = "test_sid";
        let pid = 1;
        let x1 = generate_random_scalar();
        let x2 = generate_random_scalar(); // Different private key.
        let base_point = ProjectivePoint::GENERATOR;
        let y2 = base_point * x2;

        let proof = DLogProof::prove(sid, pid, x1, base_point);

        // Verify using a different public key.
        let result = proof.verify(sid, pid, y2, base_point);

        assert!(!result, "Verification should fail for mismatched public keys");
    }
}