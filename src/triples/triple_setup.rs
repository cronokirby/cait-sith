use std::collections::HashMap;

use crate::{
    compat::CSCurve,
    participants::ParticipantList,
    protocol::{
        internal::{make_protocol, Context, PrivateChannel},
        InitializationError, Participant, Protocol, ProtocolError,
    },
};

use super::{
    batch_random_ot::{batch_random_ot_receiver, batch_random_ot_sender},
    bits::{BitVector, SquareBitMatrix},
};

/// Represents a single setup, allowing for random OT extensions later.
///
/// These random OT extensions will be used for generating triples.
///
/// The names of the variants refer to the roles each party plays in the
/// extension.
#[derive(Debug, Clone)]
pub enum SingleSetup {
    Sender(BitVector, SquareBitMatrix),
    Receiver(SquareBitMatrix, SquareBitMatrix),
}

/// Represents the setup we need for generating triples efficiently later.
///
/// This consists of a single setup for each other party in a list of participants.
#[derive(Debug, Clone)]
pub struct Setup {
    pub setups: HashMap<Participant, SingleSetup>,
}

impl Setup {
    /// This returns true if this setup can be used for a given list of participants.
    ///
    /// This will check that the setup has sufficient information for these participants.
    pub fn can_be_used_for(&self, me: Participant, participants: &ParticipantList) -> bool {
        participants
            .others(me)
            .all(|p| self.setups.contains_key(&p))
    }
}

async fn do_sender<C: CSCurve>(
    ctx: Context<'_>,
    chan: PrivateChannel,
) -> Result<SingleSetup, ProtocolError> {
    let (delta, k) = batch_random_ot_receiver::<C>(ctx, chan).await?;
    Ok(SingleSetup::Sender(delta, k))
}

async fn do_receiver<C: CSCurve>(
    ctx: Context<'_>,
    chan: PrivateChannel,
) -> Result<SingleSetup, ProtocolError> {
    let (k0, k1) = batch_random_ot_sender::<C>(ctx, chan).await?;
    Ok(SingleSetup::Receiver(k0, k1))
}

async fn do_setup<C: CSCurve>(
    ctx: Context<'_>,
    participants: ParticipantList,
    me: Participant,
) -> Result<Setup, ProtocolError> {
    let mut tasks = Vec::with_capacity(participants.len() - 1);
    for p in participants.others(me) {
        let fut = {
            let ctx = ctx.clone();
            async move {
                let chan = ctx.private_channel(me, p);
                if me < p {
                    do_sender::<C>(ctx, chan).await
                } else {
                    do_receiver::<C>(ctx, chan).await
                }
            }
        };
        tasks.push((p, ctx.spawn(fut)));
    }
    let mut setups = HashMap::new();
    for (p, task) in tasks {
        let setup = ctx.run(task).await?;
        setups.insert(p, setup);
    }
    Ok(Setup { setups })
}

/// Runs a setup protocol among all participants, to prepare for triple generation later.
///
/// This only needs to be one once, in order to generate an arbitrary number of triples.
pub fn setup<C: CSCurve>(
    participants: &[Participant],
    me: Participant,
) -> Result<impl Protocol<Output = Setup>, InitializationError> {
    let participants = ParticipantList::new(participants).ok_or_else(|| {
        InitializationError::BadParameters("participant list cannot contain duplicates".to_string())
    })?;

    if !participants.contains(me) {
        return Err(InitializationError::BadParameters(
            "participant list must contain this participant".to_string(),
        ));
    }

    let ctx = Context::new();
    let fut = do_setup::<C>(ctx.clone(), participants, me);
    Ok(make_protocol(ctx, fut))
}
