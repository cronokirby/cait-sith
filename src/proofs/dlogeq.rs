use elliptic_curve::{Field, Group};
use magikitten::Transcript;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    compat::{CSCurve, SerializablePoint},
    serde::{deserialize_scalar, encode, serialize_projective_point, serialize_scalar},
};

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
pub struct Statement<'a, C: CSCurve> {
    #[serde(serialize_with = "serialize_projective_point::<C, _>")]
    pub public0: &'a C::ProjectivePoint,
    #[serde(serialize_with = "serialize_projective_point::<C, _>")]
    pub generator1: &'a C::ProjectivePoint,
    #[serde(serialize_with = "serialize_projective_point::<C, _>")]
    pub public1: &'a C::ProjectivePoint,
}

impl<'a, C: CSCurve> Statement<'a, C> {
    /// Calculate the homomorphism we want to prove things about.
    fn phi(&self, x: &C::Scalar) -> (C::ProjectivePoint, C::ProjectivePoint) {
        (C::ProjectivePoint::generator() * x, *self.generator1 * x)
    }
}

/// The private witness for this proof.
///
/// This holds the scalar the prover needs to know.
#[derive(Clone, Copy)]
pub struct Witness<'a, C: CSCurve> {
    pub x: &'a C::Scalar,
}

/// Represents a proof of the statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<C: CSCurve> {
    #[serde(
        serialize_with = "serialize_scalar::<C, _>",
        deserialize_with = "deserialize_scalar::<C, _>"
    )]
    e: C::Scalar,
    #[serde(
        serialize_with = "serialize_scalar::<C, _>",
        deserialize_with = "deserialize_scalar::<C, _>"
    )]
    s: C::Scalar,
}

/// Prove that a witness satisfies a given statement.
///
/// We need some randomness for the proof, and also a transcript, which is
/// used for the Fiat-Shamir transform.
pub fn prove<'a, C: CSCurve>(
    rng: &mut impl CryptoRngCore,
    transcript: &mut Transcript,
    statement: Statement<'a, C>,
    witness: Witness<'a, C>,
) -> Proof<C> {
    transcript.message(STATEMENT_LABEL, &encode(&statement));

    let k = C::Scalar::random(rng);
    let big_k = statement.phi(&k);

    transcript.message(
        COMMITMENT_LABEL,
        &encode(&(
            SerializablePoint::<C>::from_projective(&big_k.0),
            SerializablePoint::<C>::from_projective(&big_k.1),
        )),
    );

    let e = C::Scalar::random(&mut transcript.challenge(CHALLENGE_LABEL));

    let s = k + e * witness.x;
    Proof { e, s }
}

/// Verify that a proof attesting to the validity of some statement.
///
/// We use a transcript in order to verify the Fiat-Shamir transformation.
#[must_use]
pub fn verify<C: CSCurve>(
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    proof: &Proof<C>,
) -> bool {
    let statement_data = encode(&statement);
    transcript.message(STATEMENT_LABEL, &statement_data);

    let (phi0, phi1) = statement.phi(&proof.s);
    let big_k0 = phi0 - *statement.public0 * proof.e;
    let big_k1 = phi1 - *statement.public1 * proof.e;

    transcript.message(
        COMMITMENT_LABEL,
        &encode(&(
            SerializablePoint::<C>::from_projective(&big_k0),
            SerializablePoint::<C>::from_projective(&big_k1),
        )),
    );

    let e = C::Scalar::random(&mut transcript.challenge(CHALLENGE_LABEL));

    e == proof.e
}

#[cfg(test)]
mod test {
    use rand_core::OsRng;

    use super::*;

    use k256::{ProjectivePoint, Scalar, Secp256k1};

    #[test]
    fn test_valid_proof_verifies() {
        let x = Scalar::generate_biased(&mut OsRng);

        let big_h = ProjectivePoint::GENERATOR * Scalar::generate_biased(&mut OsRng);
        let statement = Statement::<Secp256k1> {
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
