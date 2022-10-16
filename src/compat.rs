use digest::{Digest, FixedOutput};
use ecdsa::{
    elliptic_curve::{ops::Reduce, AffineXCoordinate, Curve, PrimeField},
    hazmat::DigestPrimitive,
};
use k256::{AffinePoint, Scalar, Secp256k1};

pub fn scalar_hash(msg: &[u8]) -> Scalar {
    let digest = <Secp256k1 as DigestPrimitive>::Digest::new_with_prefix(&msg);
    let m_bytes = Secp256k1::prehash_to_field_bytes(&digest.finalize_fixed()).unwrap();
    Option::<Scalar>::from(Scalar::from_repr(m_bytes)).unwrap()
}

pub fn x_coordinate(point: &AffinePoint) -> Scalar {
    <Scalar as Reduce<<Secp256k1 as Curve>::UInt>>::from_be_bytes_reduced(point.x())
}
