use k256::{Scalar, Secp256k1};
use magikitten::Transcript;
use rand_core::CryptoRngCore;
use serde::Serialize;

use crate::math::{EvaluationCommitment, Polynomial};
use crate::serde::encode;

const STATEMENT_LABEL: &[u8] = b"phi proof statement";
const COMMITMENT_LABEL: &[u8] = b"phi proof commitment";
const CHALLENGE_LABEL: &[u8] = b"phi proof challenge";

#[derive(Debug, Clone, Serialize)]
pub struct Statement<'a> {
    size: usize,
    domain: &'a [Scalar],
    public: &'a EvaluationCommitment,
}

impl<'a> Statement<'a> {
    fn phi(&self, f: &Polynomial) -> EvaluationCommitment {
        f.evaluate_many(self.domain).commit()
    }
}

pub struct Witness<'a> {
    f: &'a Polynomial,
}

pub struct Proof {
    e: Scalar,
    s: Polynomial,
}

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
