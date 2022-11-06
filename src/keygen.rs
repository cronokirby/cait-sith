use k256::{AffinePoint, ProjectivePoint, Scalar};
use magikitten::Transcript;
use rand_core::OsRng;

use crate::crypto::{commit, Commitment};
use crate::math::{GroupPolynomial, Polynomial};
use crate::participants::{ParticipantCounter, ParticipantList, ParticipantMap};
use crate::proofs::dlog;
use crate::protocol::internal2::{run_protocol, Context, SharedChannel};
use crate::protocol::{InitializationError, Participant, Protocol, ProtocolError};
use crate::serde::encode;

#[derive(Debug, Clone)]
pub struct KeygenOutput {
    pub private_share: Scalar,
    pub public_key: AffinePoint,
}

async fn do_keygen(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    threshold: usize,
) -> Result<KeygenOutput, ProtocolError> {
    dbg!("hello?");
    let mut rng = OsRng;
    let mut transcript = Transcript::new(b"cait-sith v0.1.0 keygen");

    // Spec 1.2
    transcript.message(b"participants", &encode(&participants));
    // To allow interop between platforms where usize is different!
    transcript.message(
        b"threshold",
        &u64::try_from(threshold).unwrap().to_be_bytes(),
    );

    // Spec 1.3
    let f = Polynomial::random(&mut rng, threshold);

    // Spec 1.4
    let mut big_f = f.commit();

    // Spec 1.5
    let my_commitment = commit(&big_f);

    // Spec 1.6
    let wait0 = chan.next_waitpoint();
    chan.send_many(wait0, &my_commitment).await;

    // Spec 2.1
    let mut all_commitments = ParticipantMap::new(&participants);
    all_commitments.put(me, my_commitment);
    while !all_commitments.full() {
        let (from, commitment) = chan.recv(wait0).await?;
        all_commitments.put(from, commitment);
    }

    // Spec 2.2
    let my_confirmation = commit(&all_commitments);

    // Spec 2.3
    transcript.message(b"confirmation", my_confirmation.as_ref());

    // Spec 2.4
    let wait1 = chan.next_waitpoint();
    chan.send_many(wait1, &my_confirmation).await;

    // Spec 2.5
    let statement = dlog::Statement {
        public: &big_f.evaluate_zero(),
    };
    let witness = dlog::Witness {
        x: &f.evaluate_zero(),
    };
    let my_phi_proof = dlog::prove(
        &mut rng,
        &mut transcript.forked(b"dlog0", &me.bytes()),
        statement,
        witness,
    );

    // Spec 2.6
    let wait2 = chan.next_waitpoint();
    chan.send_many(wait2, &(&big_f, my_phi_proof)).await;

    // Spec 2.7
    let wait3 = chan.next_waitpoint();
    for p in participants.others(me) {
        let x_i_j = f.evaluate(&p.scalar());
        chan.send_private(wait3, p, &x_i_j).await;
    }
    let mut x_i = f.evaluate(&me.scalar());

    // Spec 3.1 + 3.2
    let mut seen = ParticipantCounter::new(&participants);
    seen.put(me);
    while !seen.full() {
        let (from, confirmation): (_, Commitment) = chan.recv(wait1).await?;
        if !seen.put(from) {
            continue;
        }
        if confirmation != my_confirmation {
            return Err(ProtocolError::AssertionFailed(format!(
                "confirmation from {from:?} did not match expectation"
            )));
        }
    }

    // Spec 3.3 + 3.4, and also part of 3.6, for summing up the Fs.
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, (their_big_f, their_phi_proof)): (_, (GroupPolynomial, _)) =
            chan.recv(wait2).await?;
        if !seen.put(from) {
            continue;
        }

        if their_big_f.len() != threshold {
            return Err(ProtocolError::AssertionFailed(format!(
                "polynomial from {from:?} has the wrong length"
            )));
        }
        if commit(&their_big_f) != all_commitments[from] {
            return Err(ProtocolError::AssertionFailed(format!(
                "commitment from {from:?} did not match revealed F"
            )));
        }
        let statement = dlog::Statement {
            public: &their_big_f.evaluate_zero(),
        };
        if !dlog::verify(
            &mut transcript.forked(b"dlog0", &from.bytes()),
            statement,
            &their_phi_proof,
        ) {
            return Err(ProtocolError::AssertionFailed(format!(
                "dlog proof from {from:?} failed to verify"
            )));
        }
        big_f += &their_big_f;
    }

    // Spec 3.5 + 3.6
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, x_j_i): (_, Scalar) = chan.recv(wait3).await?;
        if !seen.put(from) {
            continue;
        }
        x_i += x_j_i;
    }

    // Spec 3.7
    if big_f.evaluate(&me.scalar()) != ProjectivePoint::GENERATOR * x_i {
        return Err(ProtocolError::AssertionFailed(
            "received bad private share".to_string(),
        ));
    }

    // Spec 3.8
    Ok(KeygenOutput {
        private_share: x_i,
        public_key: big_f.evaluate_zero().to_affine(),
    })
}

pub fn keygen(
    participants: &[Participant],
    me: Participant,
    threshold: usize,
) -> Result<impl Protocol<Output = KeygenOutput>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::BadParameters(format!(
            "participant count cannot be < 2, found: {}",
            participants.len()
        )));
    };
    // Spec 1.1
    if threshold > participants.len() {
        return Err(InitializationError::BadParameters(
            "threshold must be <= participant count".to_string(),
        ));
    }

    let participants = ParticipantList::new(participants).ok_or_else(|| {
        InitializationError::BadParameters("participant list cannot contain duplicates".to_string())
    })?;

    if !participants.contains(me) {
        return Err(InitializationError::BadParameters(
            "participant list must contain this participant".to_string(),
        ));
    }

    let ctx = Context::new();
    let fut = do_keygen(ctx.shared_channel(), participants, me, threshold);
    Ok(run_protocol(ctx, fut))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::protocol::{run_protocol, Participant};

    #[test]
    fn test_keygen() {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];
        let threshold = 3;

        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput>>)> =
            Vec::with_capacity(participants.len());

        for p in participants.iter() {
            let protocol = keygen(&participants, *p, threshold);
            assert!(protocol.is_ok());
            let protocol = protocol.unwrap();
            protocols.push((*p, Box::new(protocol)));
        }

        let result = run_protocol(protocols);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.len() == participants.len());
        assert_eq!(result[0].1.public_key, result[1].1.public_key);
        assert_eq!(result[1].1.public_key, result[2].1.public_key);

        let pub_key = result[2].1.public_key;

        let participants = vec![result[0].0, result[1].0, result[2].0];
        let shares = vec![
            result[0].1.private_share,
            result[1].1.private_share,
            result[2].1.private_share,
        ];
        let p_list = ParticipantList::new(&participants).unwrap();
        let x = p_list.lagrange(participants[0]) * shares[0]
            + p_list.lagrange(participants[1]) * shares[1]
            + p_list.lagrange(participants[2]) * shares[2];
        assert_eq!(ProjectivePoint::GENERATOR * x, pub_key);
    }
}
