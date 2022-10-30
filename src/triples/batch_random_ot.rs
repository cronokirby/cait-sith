use ck_meow::Meow;
use ecdsa::elliptic_curve::group::prime::PrimeCurveAffine;
use futures::future::join_all;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand_core::{CryptoRngCore, OsRng};
use subtle::ConditionallySelectable;

use crate::{
    constants::SECURITY_PARAMETER,
    protocol::{
        internal::{Communication, PrivateChannel},
        Participant, ProtocolError,
    },
    serde::encode,
};

use super::bits::{BitMatrix, BitVector, SEC_PARAM_8};

const BATCH_RANDOM_OT_HASH: &[u8] = b"cait-sith v0.1.0 batch ROT";

fn hash(i: usize, big_x_i: &AffinePoint, big_y: &AffinePoint, p: &ProjectivePoint) -> BitVector {
    let mut meow = Meow::new(BATCH_RANDOM_OT_HASH);
    meow.ad(&(i as u64).to_le_bytes(), false);
    meow.ad(&encode(&big_x_i), false);
    meow.ad(&encode(&big_y), false);
    meow.ad(&encode(&p.to_affine()), false);

    let mut bytes = [0u8; SEC_PARAM_8];
    meow.prf(&mut bytes, false);

    BitVector::from_bytes(&bytes)
}

pub async fn batch_random_ot_sender(
    mut chan: PrivateChannel,
) -> Result<(BitMatrix, BitMatrix), ProtocolError> {
    // Spec 1
    let y = Scalar::generate_biased(&mut OsRng);
    let big_y = ProjectivePoint::GENERATOR * y;
    let big_z = big_y * y;

    let wait0 = chan.next_waitpoint();
    let big_y_affine = big_y.to_affine();
    chan.send(wait0, &big_y_affine).await;

    let futs = (0..SECURITY_PARAMETER).map(|i| {
        let mut chan = chan.successor(i as u16);
        async move {
            let wait0 = chan.next_waitpoint();
            let big_x_i_affine: AffinePoint = chan.recv(wait0).await?;

            let y_big_x_i = big_x_i_affine.to_curve() * y;

            let big_k0 = hash(i, &big_x_i_affine, &big_y_affine, &y_big_x_i);
            let big_k1 = hash(i, &big_x_i_affine, &big_y_affine, &(y_big_x_i - big_z));

            Ok((big_k0, big_k1))
        }
    });
    let out: Result<Vec<(BitVector, BitVector)>, ProtocolError> =
        join_all(futs).await.into_iter().collect();

    let out = out?;

    let big_k0 = out.iter().map(|r| r.0).collect();
    let big_k1 = out.iter().map(|r| r.1).collect();
    Ok((big_k0, big_k1))
}

pub async fn batch_random_ot_receiver(
    mut chan: PrivateChannel,
) -> Result<(BitVector, BitMatrix), ProtocolError> {
    // Step 3
    let wait0 = chan.next_waitpoint();
    let big_y_affine: AffinePoint = chan.recv(wait0).await?;
    let big_y = big_y_affine.to_curve();

    let delta = BitVector::random(&mut OsRng);

    let futs = delta.bits().enumerate().map(|(i, d_i)| {
        let mut chan = chan.successor(i as u16);
        async move {
            // Step 4
            let x_i = Scalar::generate_biased(&mut OsRng);
            let mut big_x_i = ProjectivePoint::GENERATOR * x_i;
            big_x_i.conditional_assign(&(big_x_i + big_y), d_i);

            // Step 6
            let wait0 = chan.next_waitpoint();
            let big_x_i_affine = big_x_i.to_affine();
            chan.send(wait0, &big_x_i_affine).await;

            // Step 5
            hash(i, &big_x_i_affine, &big_y_affine, &(big_y * x_i))
        }
    });
    let out = join_all(futs).await;
    let big_k: BitMatrix = out.into_iter().collect();

    Ok((delta, big_k))
}
