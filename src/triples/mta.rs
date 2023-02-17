use k256::Scalar;
use rand_core::OsRng;
use subtle::Choice;

use crate::protocol::{
    internal::{make_protocol, Context, PrivateChannel},
    run_two_party_protocol, Participant, ProtocolError,
};

/// The sender for multiplicative to additive conversion.
pub async fn mta_sender(
    mut chan: PrivateChannel,
    v: &[(Scalar, Scalar)],
    a: Scalar,
) -> Result<Scalar, ProtocolError> {
    let wait0 = chan.next_waitpoint();
    chan.send(wait0, &a).await;

    let wait1 = chan.next_waitpoint();
    let alpha: Scalar = chan.recv(wait1).await?;

    Ok(alpha)
}

/// The receiver for multiplicative to additive conversion.
pub async fn mta_receiver(
    mut chan: PrivateChannel,
    tv: &[(Choice, Scalar)],
    b: Scalar,
) -> Result<Scalar, ProtocolError> {
    let wait0 = chan.next_waitpoint();
    let a: Scalar = chan.recv(wait0).await?;

    let beta = Scalar::generate_biased(&mut OsRng);
    let alpha = a * b - beta;
    let wait1 = chan.next_waitpoint();
    chan.send(wait1, &alpha).await;

    Ok(beta)
}

/// Run the multiplicative to additive protocol
pub(crate) fn run_mta(
    (v, a): (&[(Scalar, Scalar)], Scalar),
    (tv, b): (&[(Choice, Scalar)], Scalar),
) -> Result<(Scalar, Scalar), ProtocolError> {
    let s = Participant::from(0u32);
    let r = Participant::from(1u32);
    let ctx_s = Context::new();
    let ctx_r = Context::new();

    run_two_party_protocol(
        s,
        r,
        &mut make_protocol(ctx_s.clone(), mta_sender(ctx_s.private_channel(s, r), v, a)),
        &mut make_protocol(
            ctx_r.clone(),
            mta_receiver(ctx_r.private_channel(r, s), tv, b),
        ),
    )
}

#[cfg(test)]
mod test {
    use ecdsa::elliptic_curve::{bigint::Encoding, Curve};
    use k256::Secp256k1;
    use rand_core::RngCore;
    use subtle::ConditionallySelectable;

    use crate::constants::SECURITY_PARAMETER;

    use super::*;

    #[test]
    fn test_mta() -> Result<(), ProtocolError> {
        let batch_size = <<Secp256k1 as Curve>::UInt as Encoding>::BIT_SIZE + SECURITY_PARAMETER;

        let v: Vec<_> = (0..batch_size)
            .map(|_| {
                (
                    Scalar::generate_biased(&mut OsRng),
                    Scalar::generate_biased(&mut OsRng),
                )
            })
            .collect();
        let tv: Vec<_> = v
            .iter()
            .map(|(v0, v1)| {
                let c = Choice::from((OsRng.next_u64() & 1) as u8);
                (c, Scalar::conditional_select(v0, v1, c))
            })
            .collect();

        let a = Scalar::generate_biased(&mut OsRng);
        let b = Scalar::generate_biased(&mut OsRng);
        let (alpha, beta) = run_mta((&v, a), (&tv, b))?;

        assert_eq!(a * b, alpha + beta);

        Ok(())
    }
}
