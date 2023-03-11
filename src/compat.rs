use digest::{Digest, FixedOutput};
use ecdsa::{hazmat::DigestPrimitive, PrimeCurve};
use elliptic_curve::{ops::Reduce, point::AffineCoordinates, Curve, CurveArithmetic};
use k256::{AffinePoint, FieldBytes, Scalar, Secp256k1};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Represents a curve suitable for use in cait-sith.
pub trait CSCurve: PrimeCurve + CurveArithmetic {
    const NAME: &'static [u8];

    /// Hash an arbitrary message in order to produce a scalar.
    fn scalar_hash(msg: &[u8]) -> Self::Scalar;

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

impl CSCurve for Secp256k1 {
    const NAME: &'static [u8] = b"Secp256k1-SHA-256";

    fn scalar_hash(msg: &[u8]) -> Self::Scalar {
        let digest = <Secp256k1 as DigestPrimitive>::Digest::new_with_prefix(msg);
        let m_bytes: FieldBytes = digest.finalize_fixed();
        <Scalar as Reduce<<Secp256k1 as Curve>::Uint>>::reduce_bytes(&m_bytes)
    }

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
}

pub(crate) struct SerializablePoint<C: CSCurve>(C::AffinePoint);

impl<C: CSCurve> SerializablePoint<C> {
    pub fn to_projective(&self) -> C::ProjectivePoint {
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

pub fn scalar_hash(msg: &[u8]) -> Scalar {
    let digest = <Secp256k1 as DigestPrimitive>::Digest::new_with_prefix(msg);
    let m_bytes: FieldBytes = digest.finalize_fixed();
    <Scalar as Reduce<<Secp256k1 as Curve>::Uint>>::reduce_bytes(&m_bytes)
}

pub fn x_coordinate(point: &AffinePoint) -> Scalar {
    <Scalar as Reduce<<Secp256k1 as Curve>::Uint>>::reduce_bytes(&point.x())
}
