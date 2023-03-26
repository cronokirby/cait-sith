use elliptic_curve::{Field, ScalarPrimitive};
use magikitten::MeowRng;
use rand_core::{OsRng, RngCore};
use subtle::{Choice, ConditionallySelectable};

use crate::{
    compat::CSCurve,
    protocol::{
        internal::{make_protocol, Context, PrivateChannel},
        run_two_party_protocol, Participant, ProtocolError,
    },
};

/// The sender for multiplicative to additive conversion.
pub async fn mta_sender<C: CSCurve>(
    mut chan: PrivateChannel,
    v: Vec<(C::Scalar, C::Scalar)>,
    a: C::Scalar,
) -> Result<C::Scalar, ProtocolError> {
    let size = v.len();

    // Step 1
    let delta: Vec<_> = (0..size).map(|_| C::Scalar::random(&mut OsRng)).collect();

    // Step 2
    let c: Vec<(ScalarPrimitive<C>, ScalarPrimitive<C>)> = delta
        .iter()
        .zip(v.iter())
        .map(|(delta_i, (v0_i, v1_i))| ((*v0_i + delta_i + a).into(), (*v1_i + delta_i - a).into()))
        .collect();
    let wait0 = chan.next_waitpoint();
    chan.send(wait0, &c).await;

    // Step 7
    let wait1 = chan.next_waitpoint();
    let (chi1, seed): (ScalarPrimitive<C>, [u8; 32]) = chan.recv(wait1).await?;

    let mut alpha = delta[0] * C::Scalar::from(chi1);

    let mut prng = MeowRng::new(&seed);
    for &delta_i in &delta[1..] {
        let chi_i = C::Scalar::random(&mut prng);
        alpha += delta_i * chi_i;
    }

    Ok(-alpha)
}

/// The receiver for multiplicative to additive conversion.
pub async fn mta_receiver<C: CSCurve>(
    mut chan: PrivateChannel,
    tv: Vec<(Choice, C::Scalar)>,
    b: C::Scalar,
) -> Result<C::Scalar, ProtocolError> {
    let size = tv.len();

    // Step 3
    let wait0 = chan.next_waitpoint();
    let c: Vec<(ScalarPrimitive<C>, ScalarPrimitive<C>)> = chan.recv(wait0).await?;
    if c.len() != tv.len() {
        return Err(ProtocolError::AssertionFailed(
            "length of c was incorrect".to_owned(),
        ));
    }
    let mut m = tv.iter().zip(c.iter()).map(|((t_i, v_i), (c0_i, c1_i))| {
        C::Scalar::conditional_select(&(*c0_i).into(), &(*c1_i).into(), *t_i) - v_i
    });

    // Step 4
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let mut prng = MeowRng::new(&seed);
    let chi: Vec<C::Scalar> = (1..size).map(|_| C::Scalar::random(&mut prng)).collect();

    let mut chi1 = C::Scalar::ZERO;
    for ((t_i, _), &chi_i) in tv.iter().skip(1).zip(chi.iter()) {
        chi1 += C::Scalar::conditional_select(&chi_i, &(-chi_i), *t_i);
    }
    chi1 = b - chi1;
    chi1.conditional_assign(&(-chi1), tv[0].0);
    //chi1.conditional_negate(tv[0].0);

    // Step 5
    let mut beta = chi1 * m.next().unwrap();
    for (&chi_i, m_i) in chi.iter().zip(m) {
        beta += chi_i * m_i;
    }

    // Step 6
    let wait1 = chan.next_waitpoint();
    let chi1: ScalarPrimitive<C> = chi1.into();
    chan.send(wait1, &(chi1, seed)).await;

    Ok(beta)
}

/// Run the multiplicative to additive protocol
#[allow(dead_code, clippy::type_complexity)]
fn run_mta<C: CSCurve>(
    (v, a): (Vec<(C::Scalar, C::Scalar)>, C::Scalar),
    (tv, b): (Vec<(Choice, C::Scalar)>, C::Scalar),
) -> Result<(C::Scalar, C::Scalar), ProtocolError> {
    let s = Participant::from(0u32);
    let r = Participant::from(1u32);
    let ctx_s = Context::new();
    let ctx_r = Context::new();

    run_two_party_protocol(
        s,
        r,
        &mut make_protocol(
            ctx_s.clone(),
            mta_sender::<C>(ctx_s.private_channel(s, r), v, a),
        ),
        &mut make_protocol(
            ctx_r.clone(),
            mta_receiver::<C>(ctx_r.private_channel(r, s), tv, b),
        ),
    )
}

#[cfg(test)]
mod test {
    use ecdsa::elliptic_curve::{bigint::Bounded, Curve};
    use k256::{Scalar, Secp256k1};
    use rand_core::RngCore;

    use crate::constants::SECURITY_PARAMETER;

    use super::*;

    #[test]
    fn test_mta() -> Result<(), ProtocolError> {
        let batch_size = <<Secp256k1 as Curve>::Uint as Bounded>::BITS + SECURITY_PARAMETER;

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
        let (alpha, beta) = run_mta::<Secp256k1>((v, a), (tv, b))?;

        assert_eq!(a * b, alpha + beta);

        Ok(())
    }
}
