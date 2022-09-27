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
        Polynomial { coefficients }
    }
}
