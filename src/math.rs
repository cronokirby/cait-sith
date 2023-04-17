use std::ops::{Add, AddAssign, Index, Mul, MulAssign};

use elliptic_curve::{Field, Group};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    compat::CSCurve,
    serde::{deserialize_projective_points, serialize_projective_points},
};

/// Represents a polynomial with coefficients in the scalar field of the curve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial<C: CSCurve> {
    /// The coefficients of our polynomial, from 0..size-1.
    coefficients: Vec<C::Scalar>,
}

impl<C: CSCurve> Polynomial<C> {
    /// Generate a random polynomial with a certain number of coefficients.
    pub fn random(rng: &mut impl CryptoRngCore, size: usize) -> Self {
        let coefficients = (0..size).map(|_| C::Scalar::random(&mut *rng)).collect();
        Self { coefficients }
    }

    /// Extend a constant to a random polynomial of a certain size.
    ///
    /// This is useful if you want the polynomial to have a certain value, but
    /// otherwise be random.
    pub fn extend_random(rng: &mut impl CryptoRngCore, size: usize, constant: &C::Scalar) -> Self {
        let mut coefficients = Vec::with_capacity(size);
        coefficients.push(*constant);
        for _ in 1..size {
            coefficients.push(C::Scalar::random(&mut *rng));
        }
        Self { coefficients }
    }

    /// Modify this polynomial by adding another polynomial.
    pub fn add_mut(&mut self, other: &Self) {
        let new_len = self.coefficients.len().max(other.coefficients.len());
        self.coefficients.resize(new_len, C::Scalar::ZERO);
        self.coefficients
            .iter_mut()
            .zip(other.coefficients.iter())
            .for_each(|(a, b)| *a += b);
    }

    /// Return the addition of this polynomial with another.
    pub fn add(&self, other: &Self) -> Self {
        let mut out = self.clone();
        out.add_mut(other);
        out
    }

    /// Scale this polynomial in place by a field element.
    pub fn scale_mut(&mut self, scale: &C::Scalar) {
        self.coefficients.iter_mut().for_each(|a| *a *= scale);
    }

    /// Return the result of scaling this polynomial by a field element.
    pub fn scale(&self, scale: &C::Scalar) -> Self {
        let mut out = self.clone();
        out.scale_mut(scale);
        out
    }

    /// Evaluate this polynomial at 0.
    ///
    /// This is much more efficient than evaluating at other points.
    pub fn evaluate_zero(&self) -> C::Scalar {
        self.coefficients.get(0).cloned().unwrap_or_default()
    }

    /// Set the zero value of this polynomial to a new scalar
    pub fn set_zero(&mut self, v: C::Scalar) {
        if self.coefficients.is_empty() {
            self.coefficients.push(v)
        } else {
            self.coefficients[0] = v
        }
    }

    /// Evaluate this polynomial at a specific point.
    pub fn evaluate(&self, x: &C::Scalar) -> C::Scalar {
        let mut out = C::Scalar::ZERO;
        for c in self.coefficients.iter().rev() {
            out = out * x + c;
        }
        out
    }

    /// Commit to this polynomial by acting on the generator
    pub fn commit(&self) -> GroupPolynomial<C> {
        let coefficients = self
            .coefficients
            .iter()
            .map(|x| C::ProjectivePoint::generator() * x)
            .collect();
        GroupPolynomial { coefficients }
    }

    /// Return the length of this polynomial.
    pub fn len(&self) -> usize {
        self.coefficients.len()
    }
}

impl<C: CSCurve> Index<usize> for Polynomial<C> {
    type Output = C::Scalar;

    fn index(&self, i: usize) -> &Self::Output {
        &self.coefficients[i]
    }
}

impl<C: CSCurve> Add for &Polynomial<C> {
    type Output = Polynomial<C>;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl<C: CSCurve> AddAssign<&Self> for Polynomial<C> {
    fn add_assign(&mut self, rhs: &Self) {
        self.add_mut(rhs)
    }
}

impl<C: CSCurve> Mul<&C::Scalar> for &Polynomial<C> {
    type Output = Polynomial<C>;

    fn mul(self, rhs: &C::Scalar) -> Self::Output {
        self.scale(rhs)
    }
}

impl<C: CSCurve> MulAssign<&C::Scalar> for Polynomial<C> {
    fn mul_assign(&mut self, rhs: &C::Scalar) {
        self.scale_mut(rhs)
    }
}

/// A polynomial with group coefficients.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GroupPolynomial<C: CSCurve> {
    #[serde(
        serialize_with = "serialize_projective_points::<C, _>",
        deserialize_with = "deserialize_projective_points::<C, _>"
    )]
    coefficients: Vec<C::ProjectivePoint>,
}

impl<C: CSCurve> GroupPolynomial<C> {
    /// Modify this polynomial by adding another one.
    pub fn add_mut(&mut self, other: &Self) {
        self.coefficients
            .iter_mut()
            .zip(other.coefficients.iter())
            .for_each(|(a, b)| *a += b)
    }

    /// The result of adding this polynomial with another.
    pub fn add(&self, other: &Self) -> Self {
        let coefficients = self
            .coefficients
            .iter()
            .zip(other.coefficients.iter())
            .map(|(a, b)| *a + *b)
            .collect();
        Self { coefficients }
    }

    /// Evaluate this polynomial at 0.
    ///
    /// This is more efficient than evaluating at an arbitrary point.
    pub fn evaluate_zero(&self) -> C::ProjectivePoint {
        self.coefficients.get(0).cloned().unwrap_or_default()
    }

    /// Evaluate this polynomial at a specific value.
    pub fn evaluate(&self, x: &C::Scalar) -> C::ProjectivePoint {
        let mut out = C::ProjectivePoint::identity();
        for c in self.coefficients.iter().rev() {
            out = out * x + c;
        }
        out
    }

    /// Set the zero value of this polynomial to a new group value.
    pub fn set_zero(&mut self, v: C::ProjectivePoint) {
        if self.coefficients.is_empty() {
            self.coefficients.push(v)
        } else {
            self.coefficients[0] = v
        }
    }

    /// Return the length of this polynomial.
    pub fn len(&self) -> usize {
        self.coefficients.len()
    }
}

impl<C: CSCurve> Add for &GroupPolynomial<C> {
    type Output = GroupPolynomial<C>;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl<C: CSCurve> AddAssign<&Self> for GroupPolynomial<C> {
    fn add_assign(&mut self, rhs: &Self) {
        self.add_mut(rhs)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use k256::{Scalar, Secp256k1};

    #[test]
    fn test_addition() {
        let mut f = Polynomial::<Secp256k1> {
            coefficients: vec![Scalar::from(1u32), Scalar::from(2u32)],
        };
        let g = Polynomial {
            coefficients: vec![Scalar::from(1u32), Scalar::from(2u32), Scalar::from(3u32)],
        };
        let h = Polynomial {
            coefficients: vec![Scalar::from(2u32), Scalar::from(4u32), Scalar::from(3u32)],
        };
        assert_eq!(&f + &g, h);
        f += &g;
        assert_eq!(f, h);
    }

    #[test]
    fn test_scaling() {
        let s = Scalar::from(2u32);
        let mut f = Polynomial::<Secp256k1> {
            coefficients: vec![Scalar::from(1u32), Scalar::from(2u32)],
        };
        let h = Polynomial {
            coefficients: vec![Scalar::from(2u32), Scalar::from(4u32)],
        };
        assert_eq!(&f * &s, h);
        f *= &s;
        assert_eq!(f, h);
    }

    #[test]
    fn test_evaluation() {
        let f = Polynomial::<Secp256k1> {
            coefficients: vec![Scalar::from(1u32), Scalar::from(2u32)],
        };
        assert_eq!(f.evaluate(&Scalar::from(1u32)), Scalar::from(3u32));
        assert_eq!(f.evaluate(&Scalar::from(2u32)), Scalar::from(5u32));
    }
}
