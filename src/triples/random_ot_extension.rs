use ck_meow::Meow;
use elliptic_curve::CurveArithmetic;
use magikitten::MeowRng;
use rand_core::{OsRng, RngCore};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::{
    compat::CSCurve,
    constants::SECURITY_PARAMETER,
    protocol::{
        internal::{make_protocol, Context, PrivateChannel},
        run_two_party_protocol, Participant, ProtocolError,
    },
};

use super::{
    bits::{BitMatrix, BitVector, ChoiceVector, DoubleBitVector, SquareBitMatrix},
    correlated_ot_extension::{correlated_ot_receiver, correlated_ot_sender, CorrelatedOtParams},
};

const MEOW_CTX: &[u8] = b"Random OT Extension Hash";

fn hash_to_scalar<C: CSCurve>(i: usize, v: &BitVector) -> C::Scalar {
    let mut meow = Meow::new(MEOW_CTX);
    let i64 = u64::try_from(i).expect("failed to convert usize to u64");
    meow.meta_ad(&i64.to_le_bytes(), false);
    meow.ad(&v.bytes(), false);
    let mut seed = [0u8; 32];
    meow.prf(&mut seed, false);
    // Could in theory avoid one PRF call by using a more direct RNG wrapper
    // over the prf function, but oh well.
    C::sample_scalar_constant_time(&mut MeowRng::new(&seed))
}

fn adjust_size(size: usize) -> usize {
    let r = size % SECURITY_PARAMETER;
    let padded = if r == 0 {
        size
    } else {
        size + (SECURITY_PARAMETER - r)
    };
    padded + 2 * SECURITY_PARAMETER
}

/// Parameters we need for random OT extension
#[derive(Debug, Clone, Copy)]
pub struct RandomOtExtensionParams<'sid> {
    pub sid: &'sid [u8],
    pub batch_size: usize,
}

/// The result that the sender gets.
pub type RandomOTExtensionSenderOut<C> = Vec<(
    <C as CurveArithmetic>::Scalar,
    <C as CurveArithmetic>::Scalar,
)>;

/// The result that the receiver gets.
pub type RandomOTExtensionReceiverOut<C> = Vec<(Choice, <C as CurveArithmetic>::Scalar)>;

pub async fn random_ot_extension_sender<C: CSCurve>(
    mut chan: PrivateChannel,
    params: RandomOtExtensionParams<'_>,
    delta: BitVector,
    k: &SquareBitMatrix,
) -> Result<RandomOTExtensionSenderOut<C>, ProtocolError> {
    let adjusted_size = adjust_size(params.batch_size);

    // Step 2
    let q = correlated_ot_sender(
        chan.child(0),
        CorrelatedOtParams {
            sid: params.sid,
            batch_size: adjusted_size,
        },
        delta,
        k,
    )
    .await?;

    // Step 5
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let wait0 = chan.next_waitpoint();
    chan.send(wait0, &seed).await;

    let mu = adjusted_size / SECURITY_PARAMETER;

    // Step 7
    let mut prng = MeowRng::new(&seed);
    let chi: Vec<BitVector> = (0..mu).map(|_| BitVector::random(&mut prng)).collect();

    // Step 11
    let wait1 = chan.next_waitpoint();
    let (small_x, small_t): (DoubleBitVector, Vec<DoubleBitVector>) = chan.recv(wait1).await?;

    // Step 10
    if small_t.len() != SECURITY_PARAMETER {
        return Err(ProtocolError::AssertionFailed(
            "small t of incorrect length".to_owned(),
        ));
    }

    for (j, small_t_j) in small_t.iter().enumerate() {
        let delta_j = Choice::from(delta.bit(j) as u8);

        let mut small_q_j = DoubleBitVector::zero();
        for (q_i, chi_i) in q.column_chunks(j).zip(chi.iter()) {
            small_q_j ^= q_i.gf_mul(chi_i);
        }

        let delta_j_x =
            DoubleBitVector::conditional_select(&DoubleBitVector::zero(), &small_x, delta_j);
        if !bool::from(small_q_j.ct_eq(&(small_t_j ^ delta_j_x))) {
            return Err(ProtocolError::AssertionFailed("q check failed".to_owned()));
        }
    }

    // Step 14
    let mut out = Vec::with_capacity(params.batch_size);

    for (i, q_i) in q.rows().take(params.batch_size).enumerate() {
        let v0_i = hash_to_scalar::<C>(i, q_i);
        let v1_i = hash_to_scalar::<C>(i, &(q_i ^ delta));
        out.push((v0_i, v1_i))
    }

    Ok(out)
}

pub async fn random_ot_extension_receiver<C: CSCurve>(
    mut chan: PrivateChannel,
    params: RandomOtExtensionParams<'_>,
    k0: &SquareBitMatrix,
    k1: &SquareBitMatrix,
) -> Result<RandomOTExtensionReceiverOut<C>, ProtocolError> {
    let adjusted_size = adjust_size(params.batch_size);

    // Step 1
    let b = ChoiceVector::random(&mut OsRng, adjusted_size);
    let x: BitMatrix = b
        .bits()
        .map(|b_i| BitVector::conditional_select(&BitVector::zero(), &!BitVector::zero(), b_i))
        .collect();

    // Step 2
    let t = correlated_ot_receiver(
        chan.child(0),
        CorrelatedOtParams {
            sid: params.sid,
            batch_size: adjusted_size,
        },
        k0,
        k1,
        &x,
    )
    .await;

    let wait0 = chan.next_waitpoint();

    // Step 5
    let seed: [u8; 32] = chan.recv(wait0).await?;

    let mu = adjusted_size / SECURITY_PARAMETER;

    // Step 7
    let mut prng = MeowRng::new(&seed);
    let chi: Vec<BitVector> = (0..mu).map(|_| BitVector::random(&mut prng)).collect();

    // Step 8
    let mut small_x = DoubleBitVector::zero();
    for (b_i, chi_i) in b.chunks().zip(chi.iter()) {
        small_x.xor_mut(&b_i.gf_mul(chi_i));
    }
    let small_t: Vec<_> = (0..SECURITY_PARAMETER)
        .map(|j| {
            let mut small_t_j = DoubleBitVector::zero();
            for (t_i, chi_i) in t.column_chunks(j).zip(chi.iter()) {
                small_t_j ^= t_i.gf_mul(chi_i);
            }
            small_t_j
        })
        .collect();

    // Step 11
    let wait1 = chan.next_waitpoint();
    chan.send(wait1, &(small_x, small_t)).await;

    // Step 15
    let out: Vec<_> = b
        .bits()
        .zip(t.rows())
        .take(params.batch_size)
        .enumerate()
        .map(|(i, (b_i, t_i))| (b_i, hash_to_scalar::<C>(i, t_i)))
        .collect();

    Ok(out)
}

/// Run the random OT protocol between two parties.
#[allow(dead_code)]
fn run_random_ot<C: CSCurve>(
    (delta, k): (BitVector, &SquareBitMatrix),
    (k0, k1): (&SquareBitMatrix, &SquareBitMatrix),
    sid: &[u8],
    batch_size: usize,
) -> Result<
    (
        RandomOTExtensionSenderOut<C>,
        RandomOTExtensionReceiverOut<C>,
    ),
    ProtocolError,
> {
    let s = Participant::from(0u32);
    let r = Participant::from(1u32);
    let ctx_s = Context::new();
    let ctx_r = Context::new();

    let params = RandomOtExtensionParams { sid, batch_size };

    run_two_party_protocol(
        s,
        r,
        &mut make_protocol(
            ctx_s.clone(),
            random_ot_extension_sender::<C>(ctx_s.private_channel(s, r), params, delta, k),
        ),
        &mut make_protocol(
            ctx_r.clone(),
            random_ot_extension_receiver::<C>(ctx_r.private_channel(r, s), params, k0, k1),
        ),
    )
}

#[cfg(test)]
mod test {
    use crate::triples::batch_random_ot::run_batch_random_ot;

    use super::*;

    use k256::{Scalar, Secp256k1};

    #[test]
    fn test_random_ot() -> Result<(), ProtocolError> {
        let ((k0, k1), (delta, k)) = run_batch_random_ot::<Secp256k1>()?;
        let batch_size = 16;
        let (sender_out, receiver_out) =
            run_random_ot::<Secp256k1>((delta, &k), (&k0, &k1), b"test sid", batch_size)?;
        assert_eq!(sender_out.len(), batch_size);
        assert_eq!(receiver_out.len(), batch_size);
        for ((v0_i, v1_i), (b_i, vb_i)) in sender_out.iter().zip(receiver_out.iter()) {
            assert_eq!(*vb_i, Scalar::conditional_select(v0_i, v1_i, *b_i));
        }
        Ok(())
    }
}
