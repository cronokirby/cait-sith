use magikitten::MeowRng;
use rand_core::{OsRng, RngCore};
use subtle::ConditionallySelectable;

use crate::{
    constants::SECURITY_PARAMETER,
    crypto::{commit, Commitment},
    protocol::{internal::PrivateChannel, ProtocolError},
};

use super::{
    bits::{random_choices, BitMatrix, BitVector, SquareBitMatrix},
    correlated_ot_extension::{correlated_ot_receiver, correlated_ot_sender, CorrelatedOtParams},
};

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
) -> Result<(), ProtocolError> {
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

    todo!()
}
