use ecdsa::elliptic_curve::group::Curve;
use k256::{ProjectivePoint, Scalar};
use magikitten::Transcript;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::serde::{encode, serialize_projective_point};

/// The label we use for hashing the statement.
const STATEMENT_LABEL: &[u8] = b"dlogeq proof statement";
/// The label we use for hashing the first prover message.
const COMMITMENT_LABEL: &[u8] = b"dlogeq proof commitment";
/// The label we use for generating the challenge.
const CHALLENGE_LABEL: &[u8] = b"dlogeq proof challenge";

/// The public statement for this proof.
///
/// This statement claims knowledge of a scalar that's the discrete logarithm
/// of one point under the standard generator, and of another point under an alternate generator.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Statement<'a> {
    #[serde(serialize_with = "serialize_projective_point")]
    pub public0: &'a ProjectivePoint,
    #[serde(serialize_with = "serialize_projective_point")]
    pub generator1: &'a ProjectivePoint,
    #[serde(serialize_with = "serialize_projective_point")]
    pub public1: &'a ProjectivePoint,
}

impl<'a> Statement<'a> {
    /// Calculate the homomorphism we want to prove things about.
    fn phi(&self, x: &Scalar) -> (ProjectivePoint, ProjectivePoint) {
        (ProjectivePoint::GENERATOR * x, self.generator1 * x)
    }
}

/// The private witness for this proof.
///
/// This holds the scalar the prover needs to know.
#[derive(Clone, Copy)]
pub struct Witness<'a> {
    pub x: &'a Scalar,
}

/// Represents a proof of the statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    e: Scalar,
    s: Scalar,
}

/// Prove that a witness satisfies a given statement.
///
/// We need some randomness for the proof, and also a transcript, which is
/// used for the Fiat-Shamir transform.
pub fn prove<'a>(
    rng: &mut impl CryptoRngCore,
    transcript: &mut Transcript,
    statement: Statement<'a>,
    witness: Witness<'a>,
) -> Proof {
    transcript.message(STATEMENT_LABEL, &encode(&statement));

    let k = Scalar::generate_biased(rng);
    let big_k = statement.phi(&k);

    transcript.message(
        COMMITMENT_LABEL,
        &encode(&(big_k.0.to_affine(), big_k.1.to_affine())),
    );

    let e = Scalar::generate_biased(&mut transcript.challenge(CHALLENGE_LABEL));

    let s = k + e * witness.x;
    Proof { e, s }
}

/// Verify that a proof attesting to the validity of some statement.
///
/// We use a transcript in order to verify the Fiat-Shamir transformation.
#[must_use]
pub fn verify<'a>(transcript: &mut Transcript, statement: Statement<'a>, proof: &Proof) -> bool {
    let statement_data = encode(&statement);
    transcript.message(STATEMENT_LABEL, &statement_data);

    let (phi0, phi1) = statement.phi(&proof.s);
    let big_k0 = phi0 - statement.public0 * &proof.e;
    let big_k1 = phi1 - statement.public1 * &proof.e;

    transcript.message(
        COMMITMENT_LABEL,
        &encode(&(big_k0.to_affine(), big_k1.to_affine())),
    );

    let e = Scalar::generate_biased(&mut transcript.challenge(CHALLENGE_LABEL));

    e == proof.e
}

#[cfg(test)]
mod test {
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn test_valid_proof_verifies() {
        let x = Scalar::generate_biased(&mut OsRng);

        let big_h = ProjectivePoint::GENERATOR * Scalar::generate_biased(&mut OsRng);
        let statement = Statement {
            public0: &(ProjectivePoint::GENERATOR * x),
            generator1: &big_h,
            public1: &(big_h * x),
        };
        let witness = Witness { x: &x };

        let transcript = Transcript::new(b"protocol");

        let proof = prove(
            &mut OsRng,
            &mut transcript.forked(b"party", &[1]),
            statement,
            witness,
        );

        let ok = verify(&mut transcript.forked(b"party", &[1]), statement, &proof);

        assert!(ok);
    }
}
