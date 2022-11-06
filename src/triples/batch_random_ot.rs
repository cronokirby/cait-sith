use ck_meow::Meow;
use ecdsa::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand_core::{CryptoRngCore, OsRng};
use smol::stream::{self, StreamExt};
use subtle::ConditionallySelectable;

use crate::{
    constants::SECURITY_PARAMETER,
    protocol::{
        internal::{run_protocol, Context, PrivateChannel},
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
    ctx: Context<'_>,
    mut chan: PrivateChannel,
) -> Result<(BitMatrix, BitMatrix), ProtocolError> {
    eprintln!("I'm the sender");
    // Spec 1
    let y = Scalar::generate_biased(&mut OsRng);
    let big_y = ProjectivePoint::GENERATOR * y;
    let big_z = big_y * y;

    let wait0 = chan.next_waitpoint();
    let big_y_affine = big_y.to_affine();
    chan.send(wait0, &big_y_affine).await;

    let tasks = (0..SECURITY_PARAMETER).map(|i| {
        let mut chan = chan.successor(i as u16);
        ctx.spawn(async move {
            let wait0 = chan.next_waitpoint();
            let big_x_i_affine: AffinePoint = chan.recv(wait0).await?;
            dbg!("received big_x_i_affine");

            let y_big_x_i = big_x_i_affine.to_curve() * y;

            let big_k0 = hash(i, &big_x_i_affine, &big_y_affine, &y_big_x_i);
            let big_k1 = hash(i, &big_x_i_affine, &big_y_affine, &(y_big_x_i - big_z));

            Ok::<_, ProtocolError>((big_k0, big_k1))
        })
    });
    let out: Vec<_> = stream::iter(tasks).then(|t| t).try_collect().await?;

    let big_k0 = out.iter().map(|r| r.0).collect();
    let big_k1 = out.iter().map(|r| r.1).collect();
    Ok((big_k0, big_k1))
}

pub async fn batch_random_ot_receiver(
    ctx: Context<'_>,
    mut chan: PrivateChannel,
) -> Result<(BitVector, BitMatrix), ProtocolError> {
    eprintln!("I'm the receiver");
    // Step 3
    let wait0 = chan.next_waitpoint();
    let big_y_affine: AffinePoint = chan.recv(wait0).await?;
    let big_y = big_y_affine.to_curve();

    let delta = BitVector::random(&mut OsRng);

    let tasks = delta.bits().enumerate().map(|(i, d_i)| {
        let mut chan = chan.successor(i as u16);
        ctx.spawn(async move {
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
        })
    });
    let out: Vec<_> = stream::iter(tasks).then(|t| t).collect().await;
    let big_k: BitMatrix = out.into_iter().collect();

    Ok((delta, big_k))
}

#[cfg(test)]
mod test {
    use crate::protocol::run_two_party_protocol;

    use super::*;

    #[test]
    fn test_batch_random_ot() {
        let s = Participant::from(0u32);
        let r = Participant::from(1u32);
        let ctx_s = Context::new();
        let ctx_r = Context::new();

        let res = run_two_party_protocol(
            s,
            r,
            &mut run_protocol(
                ctx_s.clone(),
                batch_random_ot_sender(ctx_s.clone(), ctx_s.private_channel(s, r)),
            ),
            &mut run_protocol(
                ctx_r.clone(),
                batch_random_ot_receiver(ctx_r.clone(), ctx_r.private_channel(r, s)),
            ),
        );
        assert!(res.is_ok());
        let ((k0, k1), (delta, k_delta)) = res.unwrap();

        // Check that we've gotten the right rows of the two matrices.
        for (((row0, row1), delta_i), row_delta) in k0
            .rows()
            .zip(k1.rows())
            .zip(delta.bits())
            .zip(k_delta.rows())
        {
            assert_eq!(
                BitVector::conditional_select(row0, row1, delta_i),
                *row_delta
            );
        }
    }
}
