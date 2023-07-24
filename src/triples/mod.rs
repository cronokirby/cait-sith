//! This module contains the types and protocols related to triple generation.
//!
//! The cait-sith signing protocol makes use of *committed* Beaver Triples.
//! A triple is a value of the form `(a, b, c), (A, B, C)`, such that
//! `c = a * b`, and `A = a * G`, `B = b * G`, `C = c * G`. This is a beaver
//! triple along with commitments to its values in the form of group elements.
//!
//! The signing protocols make use of a triple where the scalar values `(a, b, c)`
//! are secret-shared, and the commitments are public. Each signature requires
//! two triples. These triples can be generated in advance without knowledge
//! of the secret key used to sign. It's important that the value of the underlying
//! scalars in the triple is kept secret, otherwise the private key used to create
//! a signature with that triple could be recovered.
//!
//! There are two ways of generating these triples.
//!
//! One way is to have
//! a trusted third party generate them. This is supported by the [deal] function.
//!
//! The other way is to run a protocol generating a secret shared triple without any party
//! learning the secret values. This is better because no party learns the value of the
//! triple, which needs to be kept secret. This method is supported by the [generate_triple]
//! protocol.
//!
//! This protocol requires a setup protocol to be one once beforehand.
//! After this setup protocol has been run, an arbitarary number of triples can
//! be generated.
use elliptic_curve::{Field, Group};
use rand_core::CryptoRngCore;
use serde::Serialize;

use crate::{compat::CSCurve, math::Polynomial, protocol::Participant};

/// Represents the public part of a triple.
///
/// This contains commitments to each part of the triple.
///
/// We also record who participated in the protocol,
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TriplePub<C: CSCurve> {
    pub big_a: C::AffinePoint,
    pub big_b: C::AffinePoint,
    pub big_c: C::AffinePoint,
    /// The participants in generating this triple.
    pub participants: Vec<Participant>,
    /// The threshold which will be able to reconstruct it.
    pub threshold: usize,
}

/// Represents a share of a triple.
///
/// This consists of shares of each individual part.
///
/// i.e. we have a share of a, b, and c such that a * b = c.
#[derive(Clone, Debug)]
pub struct TripleShare<C: CSCurve> {
    pub a: C::Scalar,
    pub b: C::Scalar,
    pub c: C::Scalar,
}

/// Create a new triple from scratch.
///
/// This can be used to generate a triple if you then trust the person running
/// this code to forget about the values they generated.
pub fn deal<C: CSCurve>(
    rng: &mut impl CryptoRngCore,
    participants: &[Participant],
    threshold: usize,
) -> (TriplePub<C>, Vec<TripleShare<C>>) {
    let a = C::Scalar::random(&mut *rng);
    let b = C::Scalar::random(&mut *rng);
    let c = a * b;

    let f_a = Polynomial::<C>::extend_random(rng, threshold, &a);
    let f_b = Polynomial::<C>::extend_random(rng, threshold, &b);
    let f_c = Polynomial::<C>::extend_random(rng, threshold, &c);

    let mut shares = Vec::with_capacity(participants.len());
    let mut participants_owned = Vec::with_capacity(participants.len());

    for p in participants {
        participants_owned.push(*p);
        let p_scalar = p.scalar::<C>();
        shares.push(TripleShare {
            a: f_a.evaluate(&p_scalar),
            b: f_b.evaluate(&p_scalar),
            c: f_c.evaluate(&p_scalar),
        });
    }

    let triple_pub = TriplePub {
        big_a: (C::ProjectivePoint::generator() * a).into(),
        big_b: (C::ProjectivePoint::generator() * b).into(),
        big_c: (C::ProjectivePoint::generator() * c).into(),
        participants: participants_owned,
        threshold,
    };

    (triple_pub, shares)
}

mod batch_random_ot;
mod bits;
mod correlated_ot_extension;
mod generation;
mod mta;
mod multiplication;
mod random_ot_extension;

pub use generation::{generate_triple, TripleGenerationOutput};
