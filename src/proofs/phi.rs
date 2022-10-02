use k256::Scalar;
use magikitten::Transcript;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::math::{EvaluationCommitment, Polynomial};
use crate::serde::encode;

/// The label we use for hashing the statement.
const STATEMENT_LABEL: &[u8] = b"phi proof statement";
/// The label we use for hashing the commitment (first prover message).
const COMMITMENT_LABEL: &[u8] = b"phi proof commitment";
/// The label we use for generating the challenge.
const CHALLENGE_LABEL: &[u8] = b"phi proof challenge";

/// The public statement for this proof.
///
/// This statement claims knowledge a polynomial of a given size that produces
/// the public commitment when evaluated at several points, and then moved
/// onto the group.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Statement<'a> {
    /// The size of the claimed polynomial.
    pub size: usize,
    /// The domain of points to evaluate the polynomial.
    pub domain: &'a [Scalar],
    /// The result of evaluating that polynomial and then multiplying by the generator of the group.
    pub public: &'a EvaluationCommitment,
}

impl<'a> Statement<'a> {
    /// Calculate the homomorphism we want to prove things about.
    fn phi(&self, f: &Polynomial) -> EvaluationCommitment {
        f.evaluate_many(self.domain).commit()
    }
}

/// The private witness for this proof.
///
/// This witness holds the polynomial the statement is referring to.
#[derive(Clone, Copy)]
pub struct Witness<'a> {
    pub f: &'a Polynomial,
}

/// Represents a proof of the statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    e: Scalar,
    s: Polynomial,
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
    assert_eq!(witness.f.len(), statement.size);

    transcript.message(STATEMENT_LABEL, &encode(&statement));

    let k = Polynomial::random(rng, statement.size);
    let big_k = statement.phi(&k);

    transcript.message(COMMITMENT_LABEL, &encode(&big_k));

    let e = Scalar::generate_biased(&mut transcript.challenge(CHALLENGE_LABEL));

    let s = k + e * witness.f;
    Proof { e, s }
}

/// Verify that a proof attesting to the validity of some statement.
///
/// We use a transcript in order to verify the Fiat-Shamir transformation.
#[must_use]
pub fn verify<'a>(transcript: &mut Transcript, statement: Statement<'a>, proof: &Proof) -> bool {
    if proof.s.len() != statement.size {
        return false;
    }

    let statement_data = encode(&statement);
    transcript.message(STATEMENT_LABEL, &statement_data);

    let big_k = statement.phi(&proof.s) - proof.e * statement.public;

    transcript.message(COMMITMENT_LABEL, &encode(&big_k));

    let e = Scalar::generate_biased(&mut transcript.challenge(CHALLENGE_LABEL));

    e == proof.e
}

#[cfg(test)]
mod test {
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn test_valid_proof_verifies() {
        let size = 2;
        let f = Polynomial::random(&mut OsRng, size);
        let domain = vec![Scalar::from(1u32), Scalar::from(2u32), Scalar::from(3u32)];
        let big_f = f.evaluate_many(&domain).commit();

        let statement = Statement {
            size,
            domain: &domain,
            public: &big_f,
        };
        let witness = Witness { f: &f };

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
