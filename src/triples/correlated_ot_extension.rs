use crate::protocol::{
    internal::{make_protocol, Context, PrivateChannel},
    run_two_party_protocol, Participant, ProtocolError,
};

use super::bits::{BitMatrix, BitVector, SquareBitMatrix};

/// Parameters we need for the correlated OT.
#[derive(Debug, Clone, Copy)]
pub struct CorrelatedOtParams<'sid> {
    pub(crate) sid: &'sid [u8],
    pub(crate) batch_size: usize,
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
    if u.height() != params.batch_size {
        return Err(ProtocolError::AssertionFailed(format!(
            "expected matrix of height {} found {}",
            params.batch_size,
            u.height()
        )));
    }

    // Spec 6
    let q = (u & delta) ^ t;

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

/// Run the correlated OT protocol between two parties.
#[allow(dead_code)]
fn run_correlated_ot(
    (delta, k): (BitVector, &SquareBitMatrix),
    (k0, k1, x): (&SquareBitMatrix, &SquareBitMatrix, &BitMatrix),
    sid: &[u8],
    batch_size: usize,
) -> Result<(BitMatrix, BitMatrix), ProtocolError> {
    let s = Participant::from(0u32);
    let r = Participant::from(1u32);
    let ctx_s = Context::new();
    let ctx_r = Context::new();

    let params = CorrelatedOtParams { sid, batch_size };

    run_two_party_protocol(
        s,
        r,
        &mut make_protocol(
            ctx_s.clone(),
            correlated_ot_sender(ctx_s.private_channel(s, r), params, delta, k),
        ),
        &mut make_protocol(ctx_r.clone(), async move {
            let out = correlated_ot_receiver(ctx_r.private_channel(r, s), params, k0, k1, x).await;
            Ok(out)
        }),
    )
}

#[cfg(test)]
mod test {
    use rand_core::OsRng;

    use crate::triples::batch_random_ot::run_batch_random_ot;

    use super::*;
    use k256::Secp256k1;

    #[test]
    fn test_correlated_ot() -> Result<(), ProtocolError> {
        let ((k0, k1), (delta, k)) = run_batch_random_ot::<Secp256k1>()?;
        let batch_size = 256;
        let x = BitMatrix::random(&mut OsRng, batch_size);
        let (q, t) = run_correlated_ot((delta, &k), (&k0, &k1, &x), b"test sid", batch_size)?;
        assert_eq!(t ^ (x & delta), q);
        Ok(())
    }
}
