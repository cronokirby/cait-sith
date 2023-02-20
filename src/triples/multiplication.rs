use ecdsa::elliptic_curve::{bigint::Encoding, Curve};
use k256::{Scalar, Secp256k1};

use crate::{
    constants::SECURITY_PARAMETER,
    participants::{self, ParticipantList},
    protocol::{
        internal::{Context, PrivateChannel},
        Participant, ProtocolError,
    },
};

use super::{
    bits::{BitVector, SquareBitMatrix},
    mta::{mta_receiver, mta_sender, run_mta},
    random_ot_extension::{
        random_ot_extension_receiver, random_ot_extension_sender, RandomOtExtensionParams,
    },
    Setup,
};

const BATCH_SIZE: usize = <<Secp256k1 as Curve>::UInt as Encoding>::BIT_SIZE + SECURITY_PARAMETER;

pub async fn multiplication_sender<'a>(
    ctx: Context<'a>,
    chan: PrivateChannel,
    sid: &'a [u8],
    delta: &BitVector,
    k: &SquareBitMatrix,
    a_i: &Scalar,
    b_i: &Scalar,
) -> Result<Scalar, ProtocolError> {
    // Step 1
    let mut res0 = random_ot_extension_sender(
        chan.child(0),
        RandomOtExtensionParams {
            sid,
            batch_size: 2 * BATCH_SIZE,
        },
        *delta,
        k,
    )
    .await?;
    let res1 = res0.split_off(BATCH_SIZE);

    // Step 2
    let task0 = ctx.spawn(mta_sender(chan.child(1), res0, *a_i));
    let task1 = ctx.spawn(mta_sender(chan.child(2), res1, *b_i));

    // Step 3
    let gamma0 = ctx.run(task0).await?;
    let gamma1 = ctx.run(task1).await?;

    Ok(gamma0 + gamma1)
}

pub async fn multiplication_receiver<'a>(
    ctx: Context<'a>,
    chan: PrivateChannel,
    sid: &'a [u8],
    k0: &SquareBitMatrix,
    k1: &SquareBitMatrix,
    a_i: &Scalar,
    b_i: &Scalar,
) -> Result<Scalar, ProtocolError> {
    // Step 1
    let mut res0 = random_ot_extension_receiver(
        chan.child(0),
        RandomOtExtensionParams {
            sid,
            batch_size: 2 * BATCH_SIZE,
        },
        k0,
        k1,
    )
    .await?;
    let res1 = res0.split_off(BATCH_SIZE);

    // Step 2
    let task0 = ctx.spawn(mta_receiver(chan.child(1), res0, *b_i));
    let task1 = ctx.spawn(mta_receiver(chan.child(2), res1, *a_i));

    // Step 3
    let gamma0 = ctx.run(task0).await?;
    let gamma1 = ctx.run(task1).await?;

    Ok(gamma0 + gamma1)
}

pub async fn multiplication<'a>(
    ctx: Context<'a>,
    sid: &'a [u8],
    me: Participant,
    setup: &'a Setup,
    a_i: Scalar,
    b_i: Scalar,
) -> Result<Scalar, ProtocolError> {
    let mut tasks = Vec::with_capacity(setup.setups.len());
    for (p, single_setup) in setup.setups.iter() {
        let fut = {
            let ctx = ctx.clone();
            let chan = ctx.private_channel(me, *p);
            async move {
                match single_setup {
                    super::SingleSetup::Sender(delta, k) => {
                        multiplication_sender(ctx, chan, sid, delta, k, &a_i, &b_i).await
                    }
                    super::SingleSetup::Receiver(k0, k1) => {
                        multiplication_receiver(ctx, chan, sid, k0, k1, &a_i, &b_i).await
                    }
                }
            }
        };
        tasks.push(ctx.spawn(fut));
    }
    let mut out = a_i * b_i;
    for task in tasks {
        out += task.await?;
    }
    Ok(out)
}
