use std::ops::Index;

use k256::Scalar;
use rand_core::CryptoRngCore;

/// Represents a polynomial with coefficients in the scalar field of the curve.
#[derive(Debug, Clone)]
pub struct Polynomial {
    /// The coefficients of our polynomial, from 0..size-1.
    coefficients: Vec<Scalar>,
}

impl Polynomial {
    /// Generate a random polynomial with a certain number of coefficients.
    pub fn random(rng: &mut impl CryptoRngCore, size: usize) -> Self {
        let coefficients = (0..size)
            .map(|_| Scalar::generate_biased(&mut *rng))
            .collect();
        Self { coefficients }
    }

    /// Extend a constant to a random polynomial of a certain size.
    ///
    /// This is useful if you want the polynomial to have a certain value, but
    /// otherwise be random.
    pub fn extend_random(rng: &mut impl CryptoRngCore, size: usize, constant: &Scalar) -> Self {
        let mut coefficients = Vec::with_capacity(size);
        coefficients.push(*constant);
        for _ in 1..size {
            coefficients.push(Scalar::generate_biased(&mut *rng));
        }
        Self { coefficients }
    }
}

impl Index<usize> for Polynomial {
    type Output = Scalar;

    fn index(&self, i: usize) -> &Self::Output {
        &self.coefficients[i]
    }
}
