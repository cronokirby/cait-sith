use k256::{AffinePoint, Scalar};

use crate::protocol::Participant;

/// Represents the public part of a triple.
///
/// This contains commitments to each part of the triple.
///
/// We also record who participated in the protocol,
#[derive(Clone, Debug)]
struct TriplePub {
    big_a: AffinePoint,
    big_b: AffinePoint,
    big_c: AffinePoint,
    /// The participants in generating this triple.
    participants: Vec<Participant>,
    /// The threshold which will be able to reconstruct it.
    threshold: usize,
}

/// Represents a share of a triple.
///
/// This consists of shares of each individual part.
///
/// i.e. we have a share of a, b, and c such that a * b = c.
#[derive(Clone, Debug)]
struct TripleShare {
    a: Scalar,
    b: Scalar,
    c: Scalar,
}
