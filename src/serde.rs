use std::io::Write;

use k256::{AffinePoint, ProjectivePoint};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};

/// Encode an arbitrary serializable value into a vec.
pub fn encode<T: Serialize>(val: &T) -> Vec<u8> {
    rmp_serde::encode::to_vec(val).expect("failed to encode value")
}

/// Encode an arbitrary serializable value into a writer.
pub fn encode_writer<T: Serialize, W: Write>(w: &mut W, val: &T) {
    rmp_serde::encode::write(w, val).expect("failed to encode value");
}

/// Encode an arbitrary serializable with a byte tag.
pub fn encode_with_tag<T: Serialize>(tag: u8, val: &T) -> Vec<u8> {
    // Matches rmp_serde's internal default.
    let mut out = Vec::with_capacity(128);
    out.push(tag);
    rmp_serde::encode::write(&mut out, val).expect("failed to encode value");
    out
}

/// Serialize a list of projective points.
pub fn serialize_projective_points<S: Serializer>(
    data: &[ProjectivePoint],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(data.iter().map(|x| x.to_affine()))
}

/// Deserialize projective points.
pub fn deserialize_projective_points<'de, D>(
    deserializer: D,
) -> Result<Vec<ProjectivePoint>, D::Error>
where
    D: Deserializer<'de>,
{
    let points: Vec<AffinePoint> = Deserialize::deserialize(deserializer)?;
    Ok(points.into_iter().map(ProjectivePoint::from).collect())
}

/// Serialize a single projective point.
pub fn serialize_projective_point<S: Serializer>(
    data: &ProjectivePoint,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    data.to_affine().serialize(serializer)
}

/// Deceode an arbitrary value from a slice of bytes.
pub fn decode<T: DeserializeOwned>(input: &[u8]) -> Result<T, rmp_serde::decode::Error> {
    rmp_serde::decode::from_slice(input)
}
