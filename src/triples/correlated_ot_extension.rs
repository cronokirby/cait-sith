use crate::protocol::{internal::PrivateChannel, ProtocolError};

use super::bits::{BitMatrix, BitVector, SquareBitMatrix};

/// Parameters we need for the correlated OT.
#[derive(Debug, Clone)]
pub struct CorrelatedOtParams<'sid> {
    sid: &'sid [u8],
    batch_size: usize,
}

pub async fn correlated_ot_sender(
    mut chan: PrivateChannel,
    params: CorrelatedOtParams<'_>,
    delta: BitVector,
    k: &SquareBitMatrix,
) -> Result<BitMatrix, ProtocolError> {
    // Spec 2
    let t = k.expand_transpose(params.sid, params.batch_size);

    // Spec 5
    let wait0 = chan.next_waitpoint();
    let u: BitMatrix = chan.recv(wait0).await?;

    // Spec 6
    let q = u & delta ^ t;

    Ok(q)
}

pub async fn correlated_ot_receiver(
    mut chan: PrivateChannel,
    params: CorrelatedOtParams<'_>,
    k0: &SquareBitMatrix,
    k1: &SquareBitMatrix,
    x: &BitMatrix,
) -> BitMatrix {
    assert_eq!(x.height(), params.batch_size);
    // Spec 1
    let t0 = k0.expand_transpose(params.sid, params.batch_size);
    let t1 = k1.expand_transpose(params.sid, params.batch_size);

    // Spec 3
    let u = &t0 ^ t1 ^ x;

    // Spec 4
    let wait0 = chan.next_waitpoint();
    chan.send(wait0, &u).await;

    t0
}
