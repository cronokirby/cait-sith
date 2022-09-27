use serde::Serialize;

/// Encode an arbitrary serializable value into a vec.
pub fn encode<T: Serialize + ?Sized>(val: &T) -> Vec<u8> {
    rmp_serde::encode::to_vec(val).expect("failed to encode value")
}
