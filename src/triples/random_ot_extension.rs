use ck_meow::Meow;
use ecdsa::elliptic_curve::{bigint::U512, ops::Reduce};
use k256::Scalar;
use magikitten::MeowRng;
use rand_core::{OsRng, RngCore};
use subtle::{Choice, ConditionallySelectable};

use crate::{
    constants::SECURITY_PARAMETER,
    crypto::{commit, Commitment},
    protocol::{internal::PrivateChannel, ProtocolError},
};

use super::{
    bits::{random_choices, BitMatrix, BitVector, DoubleBitVector, SquareBitMatrix},
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
pub struct RandomOtExtensionParams<'sid> {
    sid: &'sid [u8],
    batch_size: usize,
}

pub async fn random_ot_extension_sender(
    mut chan: PrivateChannel,
    params: RandomOtExtensionParams<'_>,
    delta: BitVector,
    k: &SquareBitMatrix,
) -> Result<(), ProtocolError> {
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
    todo!()
}

pub async fn random_ot_extension_receiver(
    mut chan: PrivateChannel,
    params: RandomOtExtensionParams<'_>,
    k0: &SquareBitMatrix,
    k1: &SquareBitMatrix,
) -> Result<Vec<(Choice, Scalar)>, ProtocolError> {
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
    let b = random_choices(&mut OsRng, adjusted_size);
    let x: BitMatrix = b
        .iter()
        .map(|b_i| BitVector::conditional_select(&BitVector::zero(), &!BitVector::zero(), *b_i))
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
    for (b_j, chi_j) in b.iter().zip(chi.iter()) {
        x.conditional_assign(&(x ^ chi_j), *b_j);
    }
    let mut small_t = DoubleBitVector::zero();
    for (t_j, chi_j) in t.rows().zip(chi.iter()) {
        small_t ^= t_j.gf_mul(chi_j);
    }

    // Step 11
    let wait2 = chan.next_waitpoint();
    chan.send(wait2, &(x, small_t)).await;

    let out: Vec<_> = b
        .iter()
        .zip(t.rows())
        .take(params.batch_size)
        .enumerate()
        .map(|(i, (b_i, t_i))| (*b_i, hash_to_scalar(i, t_i)))
        .collect();

    Ok(out)
}
