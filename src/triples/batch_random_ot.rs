use ck_meow::Meow;
use elliptic_curve::{Field, Group};
use rand_core::OsRng;
use smol::stream::{self, StreamExt};
use subtle::ConditionallySelectable;

use crate::{
    compat::{CSCurve, SerializablePoint},
    constants::SECURITY_PARAMETER,
    protocol::{
        internal::{make_protocol, Context, PrivateChannel},
        run_two_party_protocol, Participant, ProtocolError,
    },
    serde::encode,
};

use super::bits::{BitMatrix, BitVector, SquareBitMatrix, SEC_PARAM_8};

const BATCH_RANDOM_OT_HASH: &[u8] = b"cait-sith v0.8.0 batch ROT";

fn hash<C: CSCurve>(
    i: usize,
    big_x_i: &SerializablePoint<C>,
    big_y: &SerializablePoint<C>,
    p: &C::ProjectivePoint,
) -> BitVector {
    let mut meow = Meow::new(BATCH_RANDOM_OT_HASH);
    meow.ad(&(i as u64).to_le_bytes(), false);
    meow.ad(&encode(&big_x_i), false);
    meow.ad(&encode(&big_y), false);
    meow.ad(&encode(&SerializablePoint::<C>::from_projective(p)), false);

    let mut bytes = [0u8; SEC_PARAM_8];
    meow.prf(&mut bytes, false);

    BitVector::from_bytes(&bytes)
}

type BatchRandomOTOutputSender = (SquareBitMatrix, SquareBitMatrix);

pub async fn batch_random_ot_sender<C: CSCurve>(
    ctx: Context<'_>,
    mut chan: PrivateChannel,
) -> Result<BatchRandomOTOutputSender, ProtocolError> {
    // Spec 1
    let y = C::Scalar::random(&mut OsRng);
    let big_y = C::ProjectivePoint::generator() * y;
    let big_z = big_y * y;

    let wait0 = chan.next_waitpoint();
    let big_y_affine = SerializablePoint::<C>::from_projective(&big_y);
    chan.send(wait0, &big_y_affine).await;

    let tasks = (0..SECURITY_PARAMETER).map(|i| {
        let mut chan = chan.child(i as u64);
        ctx.spawn(async move {
            let wait0 = chan.next_waitpoint();
            let big_x_i_affine: SerializablePoint<C> = chan.recv(wait0).await?;

            let y_big_x_i = big_x_i_affine.to_projective() * y;

            let big_k0 = hash(i, &big_x_i_affine, &big_y_affine, &y_big_x_i);
            let big_k1 = hash(i, &big_x_i_affine, &big_y_affine, &(y_big_x_i - big_z));

            Ok::<_, ProtocolError>((big_k0, big_k1))
        })
    });
    let out: Vec<(BitVector, BitVector)> = stream::iter(tasks).then(|t| t).try_collect().await?;

    let big_k0: BitMatrix = out.iter().map(|r| r.0).collect();
    let big_k1: BitMatrix = out.iter().map(|r| r.1).collect();
    Ok((big_k0.try_into().unwrap(), big_k1.try_into().unwrap()))
}

type BatchRandomOTOutputReceiver = (BitVector, SquareBitMatrix);

pub async fn batch_random_ot_receiver<C: CSCurve>(
    ctx: Context<'_>,
    mut chan: PrivateChannel,
) -> Result<BatchRandomOTOutputReceiver, ProtocolError> {
    // Step 3
    let wait0 = chan.next_waitpoint();
    let big_y_affine: SerializablePoint<C> = chan.recv(wait0).await?;
    let big_y = big_y_affine.to_projective();
    if bool::from(big_y.is_identity()) {
        return Err(ProtocolError::AssertionFailed(
            "Big y in batch random OT was zero.".into(),
        ));
    }

    let delta = BitVector::random(&mut OsRng);

    let tasks = delta.bits().enumerate().map(|(i, d_i)| {
        let mut chan = chan.child(i as u64);
        ctx.spawn(async move {
            // Step 4
            let x_i = C::Scalar::random(&mut OsRng);
            let mut big_x_i = C::ProjectivePoint::generator() * x_i;
            big_x_i.conditional_assign(&(big_x_i + big_y), d_i);

            // Step 6
            let wait0 = chan.next_waitpoint();
            let big_x_i_affine = SerializablePoint::<C>::from_projective(&big_x_i);
            chan.send(wait0, &big_x_i_affine).await;

            // Step 5
            hash(i, &big_x_i_affine, &big_y_affine, &(big_y * x_i))
        })
    });
    let out: Vec<_> = stream::iter(tasks).then(|t| t).collect().await;
    let big_k: BitMatrix = out.into_iter().collect();

    Ok((delta, big_k.try_into().unwrap()))
}

/// Run the batch random OT protocol between two parties.
#[allow(dead_code)]
pub(crate) fn run_batch_random_ot<C: CSCurve>(
) -> Result<(BatchRandomOTOutputSender, BatchRandomOTOutputReceiver), ProtocolError> {
    let s = Participant::from(0u32);
    let r = Participant::from(1u32);
    let ctx_s = Context::new();
    let ctx_r = Context::new();

    run_two_party_protocol(
        s,
        r,
        &mut make_protocol(
            ctx_s.clone(),
            batch_random_ot_sender::<C>(ctx_s.clone(), ctx_s.private_channel(s, r)),
        ),
        &mut make_protocol(
            ctx_r.clone(),
            batch_random_ot_receiver::<C>(ctx_r.clone(), ctx_r.private_channel(r, s)),
        ),
    )
}

#[cfg(test)]
mod test {
    use super::*;

    use k256::Secp256k1;

    #[test]
    fn test_batch_random_ot() {
        let res = run_batch_random_ot::<Secp256k1>();
        assert!(res.is_ok());
        let ((k0, k1), (delta, k_delta)) = res.unwrap();

        // Check that we've gotten the right rows of the two matrices.
        for (((row0, row1), delta_i), row_delta) in k0
            .matrix
            .rows()
            .zip(k1.matrix.rows())
            .zip(delta.bits())
            .zip(k_delta.matrix.rows())
        {
            assert_eq!(
                BitVector::conditional_select(row0, row1, delta_i),
                *row_delta
            );
        }
    }
}
