

#[cfg(any(feature = "p256", test))]
mod p256_impl {
    use super::super::*;

    use elliptic_curve::bigint::Bounded;
    use p256::NistP256;

    impl CSCurve for NistP256 {
        const NAME: &'static [u8] = b"NistP256";
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

