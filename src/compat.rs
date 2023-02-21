use digest::{Digest, FixedOutput};
use ecdsa::{
    elliptic_curve::{ops::Reduce, AffineXCoordinate, Curve},
    hazmat::DigestPrimitive,
};
use k256::{AffinePoint, FieldBytes, Scalar, Secp256k1};

pub fn scalar_hash(msg: &[u8]) -> Scalar {
    let digest = <Secp256k1 as DigestPrimitive>::Digest::new_with_prefix(&msg);
    let m_bytes: FieldBytes = digest.finalize_fixed();
    <Scalar as Reduce<<Secp256k1 as Curve>::UInt>>::from_be_bytes_reduced(m_bytes)
}

pub fn x_coordinate(point: &AffinePoint) -> Scalar {
    <Scalar as Reduce<<Secp256k1 as Curve>::UInt>>::from_be_bytes_reduced(point.x())
}
