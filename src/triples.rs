use k256::{AffinePoint, Scalar};
use serde::Serialize;

use crate::protocol::Participant;

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
