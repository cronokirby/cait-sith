use k256::Scalar;

use crate::math::Polynomial;

struct Proof {
    e: Scalar,
    s: Polynomial,
}
