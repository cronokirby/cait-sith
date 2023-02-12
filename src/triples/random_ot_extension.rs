use ck_meow::Meow;
use ecdsa::elliptic_curve::{bigint::U512, ops::Reduce};
use k256::Scalar;
use magikitten::MeowRng;
use rand_core::{OsRng, RngCore};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::{
    constants::SECURITY_PARAMETER,
    crypto::{commit, Commitment},
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

fn hash_to_scalar(i: usize, v: &BitVector) -> Scalar {
    let mut meow = Meow::new(MEOW_CTX);
    let i64 = u64::try_from(i).expect("failed to convert usize to u64");
    meow.meta_ad(&i64.to_le_bytes(), false);
    meow.ad(&v.bytes(), false);
    let mut scalar_bytes = [0u8; 512 / 8];
    meow.prf(&mut scalar_bytes, false);
    <Scalar as Reduce<U512>>::from_le_bytes_reduced(scalar_bytes.into())
}

fn adjust_size(size: usize) -> usize {
    size + 2 * SECURITY_PARAMETER
}

/// Parameters we need for random OT extension
#[derive(Debug, Clone, Copy)]
pub struct RandomOtExtensionParams<'sid> {
    sid: &'sid [u8],
    batch_size: usize,
}

/// The result that the sender gets.
pub type RandomOTExtensionSenderOut = Vec<(Scalar, Scalar)>;

/// The result that the receiver gets.
pub type RandomOTExtensionReceiverOut = Vec<(Choice, Scalar)>;

pub async fn random_ot_extension_sender(
    mut chan: PrivateChannel,
    params: RandomOtExtensionParams<'_>,
    delta: BitVector,
    k: &SquareBitMatrix,
) -> Result<RandomOTExtensionSenderOut, ProtocolError> {
    // Step 2
    let mut seed_s = [0u8; 32];
    OsRng.fill_bytes(&mut seed_s);
    let com_s = commit(&seed_s);

    // Step 3
    let wait0 = chan.next_waitpoint();
    chan.send(wait0, &com_s).await;

    // Step 4
    let com_r: Commitment = chan.recv(wait0).await?;

    // Step 6
    let adjusted_size = adjust_size(params.batch_size);
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

    // Step 7
    let wait1 = chan.next_waitpoint();
    chan.send(wait1, &seed_s).await;

    // Step 8
    let seed_r: [u8; 32] = chan.recv(wait1).await?;
    if commit(&seed_r) != com_r {
        return Err(ProtocolError::AssertionFailed(
            "seed commitment was incorrect".to_owned(),
        ));
    }

    // Step 9
    let mut seed = seed_r;
    for i in 0..32 {
        seed[i] ^= seed_s[i];
    }
    let mut prng = MeowRng::new(&seed);

    let chi: Vec<BitVector> = (0..adjusted_size)
        .map(|_| BitVector::random(&mut prng))
        .collect();

    // Step 12
    let mut small_q = DoubleBitVector::zero();
    for (q_i, chi_i) in q.rows().zip(chi.iter()) {
        small_q ^= q_i.gf_mul(chi_i);
    }

    // Step 13
    let wait2 = chan.next_waitpoint();
    let (x, small_t): (BitVector, DoubleBitVector) = chan.recv(wait2).await?;

    if !bool::from(small_q.ct_eq(&(small_t ^ x.gf_mul(&delta)))) {
        return Err(ProtocolError::AssertionFailed("q check failed".to_owned()));
    }

    // Step 14
    let mut out = Vec::with_capacity(params.batch_size);

    for (i, q_i) in q.rows().take(params.batch_size).enumerate() {
        let v0_i = hash_to_scalar(i, q_i);
        let v1_i = hash_to_scalar(i, &(q_i ^ delta));
        out.push((v0_i, v1_i))
    }

    Ok(out)
}

pub async fn random_ot_extension_receiver(
    mut chan: PrivateChannel,
    params: RandomOtExtensionParams<'_>,
    k0: &SquareBitMatrix,
    k1: &SquareBitMatrix,
) -> Result<RandomOTExtensionReceiverOut, ProtocolError> {
    // Step 1
    let mut seed_r = [0u8; 32];
    OsRng.fill_bytes(&mut seed_r);
    let com_r = commit(&seed_r);

    // Step 3
    let wait0 = chan.next_waitpoint();
    chan.send(wait0, &com_r).await;

    // Step 4
    let com_s: Commitment = chan.recv(wait0).await?;

    let adjusted_size = adjust_size(params.batch_size);

    // Step 5
    let b = ChoiceVector::random(&mut OsRng, adjusted_size);
    let x: BitMatrix = b
        .bits()
        .map(|b_i| BitVector::conditional_select(&BitVector::zero(), &!BitVector::zero(), b_i))
        .collect();

    // Step 6
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

    // Step 7
    let wait1 = chan.next_waitpoint();
    chan.send(wait1, &seed_r).await;

    // Step 8
    let seed_s: [u8; 32] = chan.recv(wait1).await?;
    if commit(&seed_s) != com_s {
        return Err(ProtocolError::AssertionFailed(
            "seed commitment was incorrect".to_owned(),
        ));
    }

    // Step 9
    let mut seed = seed_r;
    for i in 0..32 {
        seed[i] ^= seed_s[i];
    }
    let mut prng = MeowRng::new(&seed);

    let chi: Vec<BitVector> = (0..adjusted_size)
        .map(|_| BitVector::random(&mut prng))
        .collect();

    // Step 10
    let mut x = BitVector::zero();
    for (b_j, chi_j) in b.bits().zip(chi.iter()) {
        x.conditional_assign(&(x ^ chi_j), b_j);
    }
    let mut small_t = DoubleBitVector::zero();
    for (t_j, chi_j) in t.rows().zip(chi.iter()) {
        small_t ^= t_j.gf_mul(chi_j);
    }

    // Step 11
    let wait2 = chan.next_waitpoint();
    chan.send(wait2, &(x, small_t)).await;

    // Step 15
    let out: Vec<_> = b
        .bits()
        .zip(t.rows())
        .take(params.batch_size)
        .enumerate()
        .map(|(i, (b_i, t_i))| (b_i, hash_to_scalar(i, t_i)))
        .collect();

    Ok(out)
}

/// Run the random OT protocol between two parties.
pub(crate) fn run_random_ot(
    (delta, k): (BitVector, &SquareBitMatrix),
    (k0, k1): (&SquareBitMatrix, &SquareBitMatrix),
    sid: &[u8],
    batch_size: usize,
) -> Result<(RandomOTExtensionSenderOut, RandomOTExtensionReceiverOut), ProtocolError> {
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
            random_ot_extension_sender(ctx_s.private_channel(s, r), params, delta, &k),
        ),
        &mut make_protocol(
            ctx_r.clone(),
            random_ot_extension_receiver(ctx_r.private_channel(r, s), params, &k0, &k1),
        ),
    )
}

#[cfg(test)]
mod test {
    use crate::triples::batch_random_ot::run_batch_random_ot;

    use super::*;

    #[test]
    fn test_random_ot() -> Result<(), ProtocolError> {
        let ((k0, k1), (delta, k)) = run_batch_random_ot()?;
        let batch_size = 16;
        let (sender_out, receiver_out) =
            run_random_ot((delta, &k), (&k0, &k1), b"test sid", batch_size)?;
        assert_eq!(sender_out.len(), batch_size);
        assert_eq!(receiver_out.len(), batch_size);
        for ((v0_i, v1_i), (b_i, vb_i)) in sender_out.iter().zip(receiver_out.iter()) {
            assert_eq!(*vb_i, Scalar::conditional_select(v0_i, v1_i, *b_i));
        }
        Ok(())
    }
}
