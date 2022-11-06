use rand_core::CryptoRngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::constants::SECURITY_PARAMETER;

pub const SEC_PARAM_64: usize = (SECURITY_PARAMETER + 64 - 1) / 64;
pub const SEC_PARAM_8: usize = (SECURITY_PARAMETER + 8 - 1) / 8;

/// Represents a vector of bits.
///
/// This vector will have the size of our security parameter, which is useful
/// for most of our OT extension protocols.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BitVector([u64; SEC_PARAM_64]);

impl BitVector {
    /// Return a random bit vector.
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut out = [0u64; SEC_PARAM_64];
        for o in &mut out {
            *o = rng.next_u64();
        }
        Self(out)
    }

    pub fn from_bytes(bytes: &[u8; SEC_PARAM_8]) -> Self {
        let u64s = bytes
            .chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()));
        let mut out = [0u64; SEC_PARAM_64];
        for (o, u) in out.iter_mut().zip(u64s) {
            *o = u;
        }
        Self(out)
    }

    /// Iterate over the bits of this vector.
    pub fn bits(&self) -> impl Iterator<Item = Choice> {
        self.0
            .into_iter()
            .flat_map(|u| (0..64).map(move |j| ((u >> j) & 1).ct_eq(&0)))
    }
}

impl ConditionallySelectable for BitVector {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut out = [0u64; SEC_PARAM_64];
        for ((o_i, a_i), b_i) in out.iter_mut().zip(a.0.iter()).zip(b.0.iter()) {
            *o_i = u64::conditional_select(a_i, b_i, choice);
        }
        Self(out)
    }
}

/// Represents a matrix of bits.
///
/// Each row of this matrix is a `BitVector`, although we might have more or less
/// rows.
///
/// This is a fundamental object used for our OT extension protocol.
#[derive(Debug, Clone, PartialEq)]
pub struct BitMatrix(Vec<BitVector>);

impl BitMatrix {
    /// Create a new matrix from a list of rows.
    pub fn from_rows<'a>(rows: impl IntoIterator<Item = &'a BitVector>) -> Self {
        Self(rows.into_iter().copied().collect())
    }

    /// Return the number of rows in this matrix.
    pub fn height(&self) -> usize {
        self.0.len()
    }

    /// Iterate over the rows of this matrix.
    pub fn rows(&self) -> impl Iterator<Item = &BitVector> {
        self.0.iter()
    }
}

impl FromIterator<BitVector> for BitMatrix {
    fn from_iter<T: IntoIterator<Item = BitVector>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}
