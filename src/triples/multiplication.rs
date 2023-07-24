use crate::{
    compat::CSCurve,
    constants::SECURITY_PARAMETER,
    crypto::Digest,
    participants::ParticipantList,
    protocol::{
        internal::{Context, PrivateChannel},
        Participant, ProtocolError,
    },
};

use super::{
    batch_random_ot::{batch_random_ot_receiver, batch_random_ot_sender},
    mta::{mta_receiver, mta_sender},
    random_ot_extension::{
        random_ot_extension_receiver, random_ot_extension_sender, RandomOtExtensionParams,
    },
};

pub async fn multiplication_sender<'a, C: CSCurve>(
    ctx: Context<'a>,
    chan: PrivateChannel,
    sid: &[u8],
    a_i: &C::Scalar,
    b_i: &C::Scalar,
) -> Result<C::Scalar, ProtocolError> {
    // First, run a fresh batch random OT ourselves
    let (delta, k) = batch_random_ot_receiver::<C>(ctx.clone(), chan.child(0)).await?;

    let batch_size = C::BITS + SECURITY_PARAMETER;
    // Step 1
    let mut res0 = random_ot_extension_sender::<C>(
        chan.child(1),
        RandomOtExtensionParams {
            sid,
            batch_size: 2 * batch_size,
        },
        delta,
        &k,
    )
    .await?;
    let res1 = res0.split_off(batch_size);

    // Step 2
    let task0 = ctx.spawn(mta_sender::<C>(chan.child(2), res0, *a_i));
    let task1 = ctx.spawn(mta_sender::<C>(chan.child(3), res1, *b_i));

    // Step 3
    let gamma0 = ctx.run(task0).await?;
    let gamma1 = ctx.run(task1).await?;

    Ok(gamma0 + gamma1)
}

pub async fn multiplication_receiver<'a, C: CSCurve>(
    ctx: Context<'a>,
    chan: PrivateChannel,
    sid: &[u8],
    a_i: &C::Scalar,
    b_i: &C::Scalar,
) -> Result<C::Scalar, ProtocolError> {
    // First, run a fresh batch random OT ourselves
    let (k0, k1) = batch_random_ot_sender::<C>(ctx.clone(), chan.child(0)).await?;

    let batch_size = C::BITS + SECURITY_PARAMETER;
    // Step 1
    let mut res0 = random_ot_extension_receiver::<C>(
        chan.child(1),
        RandomOtExtensionParams {
            sid,
            batch_size: 2 * batch_size,
        },
        &k0,
        &k1,
    )
    .await?;
    let res1 = res0.split_off(batch_size);

    // Step 2
    let task0 = ctx.spawn(mta_receiver::<C>(chan.child(2), res0, *b_i));
    let task1 = ctx.spawn(mta_receiver::<C>(chan.child(3), res1, *a_i));

    // Step 3
    let gamma0 = ctx.run(task0).await?;
    let gamma1 = ctx.run(task1).await?;

    Ok(gamma0 + gamma1)
}

pub async fn multiplication<C: CSCurve>(
    ctx: Context<'_>,
    sid: Digest,
    participants: ParticipantList,
    me: Participant,
    a_i: C::Scalar,
    b_i: C::Scalar,
) -> Result<C::Scalar, ProtocolError> {
    let mut tasks = Vec::with_capacity(participants.len() - 1);
    for p in participants.others(me) {
        let fut = {
            let ctx = ctx.clone();
            let chan = ctx.private_channel(me, p);
            async move {
                if p < me {
                    multiplication_sender::<C>(ctx, chan, sid.as_ref(), &a_i, &b_i).await
                } else {
                    multiplication_receiver::<C>(ctx, chan, sid.as_ref(), &a_i, &b_i).await
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
    use k256::{Scalar, Secp256k1};
    use rand_core::OsRng;

    use crate::{
        crypto::hash,
        participants::ParticipantList,
        protocol::{
            internal::{make_protocol, Context},
            run_protocol, Participant, Protocol, ProtocolError,
        },
    };

    use super::multiplication;

    #[test]
    fn test_multiplication() -> Result<(), ProtocolError> {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];

        let prep: Vec<_> = participants
            .iter()
            .map(|p| {
                let a_i = Scalar::generate_biased(&mut OsRng);
                let b_i = Scalar::generate_biased(&mut OsRng);
                (p, a_i, b_i)
            })
            .collect();
        let a = prep
            .iter()
            .fold(Scalar::ZERO, |acc, (_, a_i, _)| acc + a_i);
        let b = prep
            .iter()
            .fold(Scalar::ZERO, |acc, (_, _, b_i)| acc + b_i);

        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = Scalar>>)> =
            Vec::with_capacity(prep.len());

        let sid = hash(b"sid");

        for (p, a_i, b_i) in prep {
            let ctx = Context::new();
            let prot = make_protocol(
                ctx.clone(),
                multiplication::<Secp256k1>(
                    ctx,
                    sid,
                    ParticipantList::new(&participants).unwrap(),
                    *p,
                    a_i,
                    b_i,
                ),
            );
            protocols.push((*p, Box::new(prot)))
        }

        let result = run_protocol(protocols)?;
        let c = result
            .into_iter()
            .fold(Scalar::ZERO, |acc, (_, c_i)| acc + c_i);

        assert_eq!(a * b, c);

        Ok(())
    }
}
