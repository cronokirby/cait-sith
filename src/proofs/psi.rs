use ::serde::Serialize;
use k256::{ProjectivePoint, Scalar};
use magikitten::Transcript;
use rand_core::CryptoRngCore;

use crate::math::{EvaluationCommitment, Polynomial};
use crate::serde::{encode, serialize_projective_point};

/// The label we use for hashing the statement.
const STATEMENT_LABEL: &[u8] = b"psi proof statement";
/// The label we use for one of the prover's first messages.
const EVALUATION_COMMITMENT_LABEL: &[u8] = b"psi proof evaluation commitment";
/// The label we use for the other first message from the prover.
const POINT_COMMITMENT_LABEL: &[u8] = b"psi proof point commitment";
/// The label we use for generating the challenge.
const CHALLENGE_LABEL: &[u8] = b"psi proof challenge";

/// The public statement for this proof.
///
/// This statement claims knowledge of two things:
/// - A polynomial of some size which produces the commitment when evaluated on the domain.
/// - A scalar which produces the public point when multiplied by the generator.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Statement<'a> {
    pub size: usize,
    pub domain: &'a [Scalar],
    pub public_commitment: &'a EvaluationCommitment,
    #[serde(serialize_with = "serialize_projective_point")]
    pub public_point: &'a ProjectivePoint,
}

impl<'a> Statement<'a> {
    fn phi(&self, f: &Polynomial, d: &Scalar) -> (EvaluationCommitment, ProjectivePoint) {
        (
            f.evaluate_many(self.domain).commit(),
            k256::ProjectivePoint::GENERATOR * d,
        )
    }
}

/// The private witness for this proof.
///
/// This holds the polynomial and scalar the proof refers to.
#[derive(Clone, Copy)]
pub struct Witness<'a> {
    pub f: &'a Polynomial,
    pub d: &'a Scalar,
}

/// Represents a proof of the statement.
#[derive(Debug, Clone)]
pub struct Proof {
    e: Scalar,
    s_poly: Polynomial,
    s_scalar: Scalar,
}

/// Prove that a witness satisfies the statement.
///
/// We need randomness for generating the proof, and a transcript,
/// used for the Fiat-Shamir transform.
pub fn prove<'a>(
    rng: &mut impl CryptoRngCore,
    transcript: &mut Transcript,
    statement: Statement<'a>,
    witness: Witness<'a>,
) -> Proof {
    assert_eq!(witness.f.len(), statement.size);

    transcript.message(STATEMENT_LABEL, &encode(&statement));

    let k_poly = Polynomial::random(rng, statement.size);
    let k_scalar = Scalar::generate_biased(rng);

    let (big_k_poly, big_k_scalar) = statement.phi(&k_poly, &k_scalar);
    transcript.message(EVALUATION_COMMITMENT_LABEL, &encode(&big_k_poly));
    transcript.message(POINT_COMMITMENT_LABEL, &encode(&big_k_scalar.to_affine()));

    let e = Scalar::generate_biased(&mut transcript.challenge(CHALLENGE_LABEL));

    let s_poly = k_poly + e * witness.f;
    let s_scalar = k_scalar + e * witness.d;

    Proof {
        e,
        s_poly,
        s_scalar,
    }
}

/// Verify that a proof correctly attests to the validity of some statement.
///
/// We use a transcript in order to reproduce the Fiat-Shamir transform.
#[must_use]
pub fn verify<'a>(transcript: &mut Transcript, statement: Statement<'a>, proof: &Proof) -> bool {
    if proof.s_poly.len() != statement.size {
        return false;
    }

    transcript.message(STATEMENT_LABEL, &encode(&statement));

    let (mut big_k_poly, mut big_k_scalar) = statement.phi(&proof.s_poly, &proof.s_scalar);
    big_k_poly = big_k_poly - proof.e * statement.public_commitment;
    big_k_scalar -= statement.public_point * &proof.e;

    transcript.message(EVALUATION_COMMITMENT_LABEL, &encode(&big_k_poly));
    transcript.message(POINT_COMMITMENT_LABEL, &encode(&big_k_scalar.to_affine()));

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
        let d = Scalar::generate_biased(&mut OsRng);
        let domain = vec![Scalar::from(1u32), Scalar::from(2u32), Scalar::from(3u32)];
        let big_f = f.evaluate_many(&domain).commit();
        let big_d = ProjectivePoint::GENERATOR * d;

        let statement = Statement {
            size,
            domain: &domain,
            public_commitment: &big_f,
            public_point: &big_d,
        };
        let witness = Witness { f: &f, d: &d };

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
