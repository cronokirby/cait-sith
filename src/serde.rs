use k256::ProjectivePoint;
use serde::{Serialize, Serializer};

/// Encode an arbitrary serializable value into a vec.
pub fn encode<T: Serialize + ?Sized>(val: &T) -> Vec<u8> {
    rmp_serde::encode::to_vec(val).expect("failed to encode value")
}

/// Serialize a list of projective points.
pub fn serialize_projective_points<S: Serializer>(
    data: &[ProjectivePoint],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(data.iter().map(|x| x.to_affine()))
}

/// Serialize a single projective point.
pub fn serialize_projective_point<S: Serializer>(
    data: &ProjectivePoint,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    data.to_affine().serialize(serializer)
}
