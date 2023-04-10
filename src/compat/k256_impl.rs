
#[cfg(any(feature = "k256", test))]
mod k256_impl {
    use super::super::*;

    use elliptic_curve::bigint::Bounded;
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
    }
}

#[cfg(test)]
mod test_scalar_hash {
    use super::super::*;

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