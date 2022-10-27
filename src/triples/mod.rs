use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand_core::CryptoRngCore;
use serde::Serialize;

use crate::{math::Polynomial, protocol::Participant};

/// Represents the public part of a triple.
///
/// This contains commitments to each part of the triple.
///
/// We also record who participated in the protocol,
#[derive(Clone, Debug, Serialize)]
pub struct TriplePub {
    pub big_a: AffinePoint,
    pub big_b: AffinePoint,
    pub big_c: AffinePoint,
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
pub struct TripleShare {
    pub a: Scalar,
    pub b: Scalar,
    pub c: Scalar,
}

/// Create a new triple from scratch.
///
/// This can be used to generate a triple if you then trust the person running
/// this code to forget about the values they generated.
pub fn deal(
    rng: &mut impl CryptoRngCore,
    participants: &[Participant],
    threshold: usize,
) -> (TriplePub, Vec<TripleShare>) {
    let a = Scalar::generate_biased(&mut *rng);
    let b = Scalar::generate_biased(&mut *rng);
    let c = a * b;

    let f_a = Polynomial::extend_random(rng, threshold, &a);
    let f_b = Polynomial::extend_random(rng, threshold, &b);
    let f_c = Polynomial::extend_random(rng, threshold, &c);

    let mut shares = Vec::with_capacity(participants.len());
    let mut participants_owned = Vec::with_capacity(participants.len());

    for p in participants {
        participants_owned.push(*p);
        let p_scalar = p.scalar();
        shares.push(TripleShare {
            a: f_a.evaluate(&p_scalar),
            b: f_b.evaluate(&p_scalar),
            c: f_c.evaluate(&p_scalar),
        });
    }

    let triple_pub = TriplePub {
        big_a: (ProjectivePoint::GENERATOR * a).to_affine(),
        big_b: (ProjectivePoint::GENERATOR * b).to_affine(),
        big_c: (ProjectivePoint::GENERATOR * c).to_affine(),
        participants: participants_owned,
        threshold,
    };

    (triple_pub, shares)
}

mod batch_random_ot;
