use ecdsa::elliptic_curve::{bigint::Bounded, Curve};
use k256::{Scalar, Secp256k1};

use crate::{
    constants::SECURITY_PARAMETER,
    crypto::Digest,
    protocol::{
        internal::{Context, PrivateChannel},
        Participant, ProtocolError,
    },
};

use super::{
    bits::{BitVector, SquareBitMatrix},
    mta::{mta_receiver, mta_sender},
    random_ot_extension::{
        random_ot_extension_receiver, random_ot_extension_sender, RandomOtExtensionParams,
    },
    Setup,
};

const BATCH_SIZE: usize = <<Secp256k1 as Curve>::Uint as Bounded>::BITS + SECURITY_PARAMETER;

pub async fn multiplication_sender<'a>(
    ctx: Context<'a>,
    chan: PrivateChannel,
    sid: &[u8],
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
    sid: &[u8],
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

pub async fn multiplication(
    ctx: Context<'_>,
    sid: Digest,
    me: Participant,
    setup: Setup,
    a_i: Scalar,
    b_i: Scalar,
) -> Result<Scalar, ProtocolError> {
    let mut tasks = Vec::with_capacity(setup.setups.len());
    for (p, single_setup) in setup.setups.into_iter() {
        let fut = {
            let ctx = ctx.clone();
            let chan = ctx.private_channel(me, p);
            async move {
                match single_setup {
                    super::SingleSetup::Sender(delta, k) => {
                        multiplication_sender(ctx, chan, sid.as_ref(), &delta, &k, &a_i, &b_i).await
                    }
                    super::SingleSetup::Receiver(k0, k1) => {
                        multiplication_receiver(ctx, chan, sid.as_ref(), &k0, &k1, &a_i, &b_i).await
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

#[cfg(test)]
mod test {
    use k256::Scalar;
    use rand_core::OsRng;

    use crate::{
        crypto::hash,
        protocol::{
            internal::{make_protocol, Context},
            run_protocol, Participant, Protocol, ProtocolError,
        },
        triples::{setup, Setup},
    };

    use super::multiplication;

    #[test]
    fn test_multiplication() -> Result<(), ProtocolError> {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];

        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = Setup>>)> =
            Vec::with_capacity(participants.len());

        for p in participants.iter() {
            let protocol = setup(&participants, *p);
            assert!(protocol.is_ok());
            let protocol = protocol.unwrap();
            protocols.push((*p, Box::new(protocol)));
        }

        let result = run_protocol(protocols)?;

        let prep: Vec<_> = result
            .into_iter()
            .map(|(p, setup)| {
                let a_i = Scalar::generate_biased(&mut OsRng);
                let b_i = Scalar::generate_biased(&mut OsRng);
                (p, setup, a_i, b_i)
            })
            .collect();
        let a = prep
            .iter()
            .fold(Scalar::ZERO, |acc, (_, _, a_i, _)| acc + a_i);
        let b = prep
            .iter()
            .fold(Scalar::ZERO, |acc, (_, _, _, b_i)| acc + b_i);

        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = Scalar>>)> =
            Vec::with_capacity(prep.len());

        let sid = hash(b"sid");

        for (p, setup, a_i, b_i) in prep {
            let ctx = Context::new();
            let prot = make_protocol(ctx.clone(), multiplication(ctx, sid, p, setup, a_i, b_i));
            protocols.push((p, Box::new(prot)))
        }

        let result = run_protocol(protocols)?;
        let c = result
            .into_iter()
            .fold(Scalar::ZERO, |acc, (_, c_i)| acc + c_i);

        assert_eq!(a * b, c);

        Ok(())
    }
}
