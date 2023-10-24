use elliptic_curve::{ops::Reduce, point::AffineCoordinates, Curve, CurveArithmetic, PrimeCurve};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Represents a curve suitable for use in cait-sith.
///
/// This is the trait that any curve usable in this library must implement.
/// This library does provide a few feature-gated implementations for curves
/// itself, beyond that you'll need to implement this trait yourself.
///
/// The bulk of the trait are the bounds requiring a curve according
/// to RustCrypto's traits.
///
/// Beyond that, we also require that curves have a name, for domain separation,
/// and a way to serialize points with serde.
pub trait CSCurve: PrimeCurve + CurveArithmetic {
    const NAME: &'static [u8];

    const BITS: usize;
    /// Serialize a point with serde.
    fn serialize_point<S: Serializer>(
        point: &Self::AffinePoint,
        serializer: S,
    ) -> Result<S::Ok, S::Error>;

    /// Deserialize a point with serde.
    fn deserialize_point<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self::AffinePoint, D::Error>;

    /// A function to sample a random scalar, guaranteed to be constant-time.
    ///
    /// By this, it's meant that we will make pull a fixed amount of
    /// data from the rng.
    fn sample_scalar_constant_time<R: CryptoRngCore>(r: &mut R) -> Self::Scalar;
}

#[cfg(any(feature = "k256", test))]
mod k256_impl {
    use super::*;

    use elliptic_curve::bigint::{Bounded, U512};
    use k256::Secp256k1;

    impl CSCurve for Secp256k1 {
        const NAME: &'static [u8] = b"Secp256k1";
        const BITS: usize = <Self::Uint as Bounded>::BITS;

        fn serialize_point<S: Serializer>(
            point: &Self::AffinePoint,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            point.serialize(serializer)
        }

        fn deserialize_point<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Self::AffinePoint, D::Error> {
            Self::AffinePoint::deserialize(deserializer)
        }

        fn sample_scalar_constant_time<R: CryptoRngCore>(r: &mut R) -> Self::Scalar {
            let mut data = [0u8; 64];
            r.fill_bytes(&mut data);
            <Self::Scalar as Reduce<U512>>::reduce_bytes(&data.into())
        }
    }
}

#[cfg(test)]
mod test_scalar_hash {
    use super::*;

    use digest::{Digest, FixedOutput};
    use ecdsa::hazmat::DigestPrimitive;
    use elliptic_curve::{ops::Reduce, Curve};
    use k256::{FieldBytes, Scalar, Secp256k1};

    #[cfg(test)]
    pub(crate) fn scalar_hash(msg: &[u8]) -> <Secp256k1 as CurveArithmetic>::Scalar {
        let digest = <Secp256k1 as DigestPrimitive>::Digest::new_with_prefix(msg);
        let m_bytes: FieldBytes = digest.finalize_fixed();
        <Scalar as Reduce<<Secp256k1 as Curve>::Uint>>::reduce_bytes(&m_bytes)
    }
}

#[cfg(test)]
pub(crate) use test_scalar_hash::scalar_hash;

#[derive(Clone, Copy)]
pub(crate) struct SerializablePoint<C: CSCurve>(C::AffinePoint);

impl<C: CSCurve> SerializablePoint<C> {
    pub fn to_projective(self) -> C::ProjectivePoint {
        self.0.into()
    }

    pub fn from_projective(point: &C::ProjectivePoint) -> Self {
        Self((*point).into())
    }
}

impl<C: CSCurve> Serialize for SerializablePoint<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        C::serialize_point(&self.0, serializer)
    }
}

impl<'de, C: CSCurve> Deserialize<'de> for SerializablePoint<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let affine = C::deserialize_point(deserializer)?;
        Ok(Self(affine))
    }
}

/// Get the x coordinate of a point, as a scalar
pub(crate) fn x_coordinate<C: CSCurve>(point: &C::AffinePoint) -> C::Scalar {
    <C::Scalar as Reduce<<C as Curve>::Uint>>::reduce_bytes(&point.x())
}
