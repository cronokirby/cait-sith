use elliptic_curve::{ops::Reduce, point::AffineCoordinates, Curve, CurveArithmetic, PrimeCurve};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod k256_impl;
pub mod p256_impl;

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
}


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

