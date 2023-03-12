use std::io::Write;

use crate::compat::{CSCurve, SerializablePoint};
use ecdsa::elliptic_curve::ScalarPrimitive;
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};

/// Encode an arbitrary serializable value into a vec.
pub fn encode<T: Serialize>(val: &T) -> Vec<u8> {
    rmp_serde::encode::to_vec(val).expect("failed to encode value")
}

/// Encode an arbitrary serializable value into a writer.
pub fn encode_writer<T: Serialize, W: Write>(w: &mut W, val: &T) {
    rmp_serde::encode::write(w, val).expect("failed to encode value");
}

/// Encode an arbitrary serializable with a tag.
pub fn encode_with_tag<T: Serialize>(tag: &[u8], val: &T) -> Vec<u8> {
    // Matches rmp_serde's internal default.
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(tag);
    rmp_serde::encode::write(&mut out, val).expect("failed to encode value");
    out
}

/// Serialize a list of projective points.
pub fn serialize_projective_points<C: CSCurve, S: Serializer>(
    data: &[C::ProjectivePoint],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(data.iter().map(SerializablePoint::<C>::from_projective))
}

/// Deserialize projective points.
pub fn deserialize_projective_points<'de, C, D>(
    deserializer: D,
) -> Result<Vec<C::ProjectivePoint>, D::Error>
where
    C: CSCurve,
    D: Deserializer<'de>,
{
    let points: Vec<SerializablePoint<C>> = Deserialize::deserialize(deserializer)?;
    Ok(points.into_iter().map(|p| p.to_projective()).collect())
}

/// Serialize a single projective point.
pub fn serialize_projective_point<C: CSCurve, S: Serializer>(
    data: &C::ProjectivePoint,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    SerializablePoint::<C>::from_projective(data).serialize(serializer)
}

/// Serialize an arbitrary scalar.
pub fn serialize_scalar<C: CSCurve, S: Serializer>(
    data: &C::Scalar,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let data: ScalarPrimitive<C> = (*data).into();
    data.serialize(serializer)
}

/// Deserialize an arbitrary scalar.
pub fn deserialize_scalar<'de, C, D>(deserializer: D) -> Result<C::Scalar, D::Error>
where
    C: CSCurve,
    D: Deserializer<'de>,
{
    let out: ScalarPrimitive<C> = ScalarPrimitive::deserialize(deserializer)?;
    Ok(out.into())
}

/// Decode an arbitrary value from a slice of bytes.
pub fn decode<T: DeserializeOwned>(input: &[u8]) -> Result<T, rmp_serde::decode::Error> {
    rmp_serde::decode::from_slice(input)
}
