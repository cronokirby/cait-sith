use k256::{ProjectivePoint, Scalar};
use magikitten::Transcript;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::serde::{encode, serialize_projective_point};

/// The label we use for hashing the statement.
const STATEMENT_LABEL: &[u8] = b"dlog proof statement";
/// The label we use for hashing the first prover message.
const COMMITMENT_LABEL: &[u8] = b"dlog proof commitment";
/// The label we use for generating the challenge.
const CHALLENGE_LABEL: &[u8] = b"dlog proof challenge";

/// The public statement for this proof.
///
/// This statement claims knowledge of the discrete logarithm of some point.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Statement<'a> {
    #[serde(serialize_with = "serialize_projective_point")]
    pub public: &'a ProjectivePoint,
}

impl<'a> Statement<'a> {
    /// Calculate the homomorphism we want to prove things about.
    fn phi(&self, x: &Scalar) -> ProjectivePoint {
        ProjectivePoint::GENERATOR * x
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

    transcript.message(COMMITMENT_LABEL, &encode(&big_k.to_affine()));

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

    let big_k = statement.phi(&proof.s) - statement.public * &proof.e;

    transcript.message(COMMITMENT_LABEL, &encode(&big_k.to_affine()));

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

        let statement = Statement {
            public: &(ProjectivePoint::GENERATOR * x),
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
