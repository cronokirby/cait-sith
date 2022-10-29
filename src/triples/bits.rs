use crate::constants::SECURITY_PARAMETER;

const SEC_PARAM_64: usize = (SECURITY_PARAMETER + 64 - 1) / 64;

/// Represents a vector of bits.
///
/// This vector will have the size of our security parameter, which is useful
/// for most of our OT extension protocols.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BitVector([u64; SEC_PARAM_64]);

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
    pub fn from_rows(rows: &[BitVector]) -> Self {
        Self(rows.iter().copied().collect())
    }

    /// Return the number of rows in this matrix.
    pub fn height(&self) -> usize {
        self.0.len()
    }
}


