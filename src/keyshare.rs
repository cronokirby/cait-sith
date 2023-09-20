use elliptic_curve::{Field, Group, ScalarPrimitive};
use magikitten::Transcript;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::compat::CSCurve;
use crate::crypto::{commit, hash, Digest};
use crate::math::{GroupPolynomial, Polynomial};
use crate::participants::{ParticipantCounter, ParticipantList, ParticipantMap};
use crate::proofs::dlog;
use crate::protocol::internal::{make_protocol, Context, SharedChannel};
use crate::protocol::{InitializationError, Participant, Protocol, ProtocolError};
use crate::serde::encode;

const LABEL: &[u8] = b"cait-sith v0.8.0 keygen";

async fn do_keyshare<C: CSCurve>(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    threshold: usize,
    s_i: C::Scalar,
    big_s: Option<C::ProjectivePoint>,
) -> Result<(C::Scalar, C::AffinePoint), ProtocolError> {
    let mut rng = OsRng;
    let mut transcript = Transcript::new(LABEL);

    // Spec 1.2
    transcript.message(b"group", C::NAME);
    transcript.message(b"participants", &encode(&participants));
    // To allow interop between platforms where usize is different!
    transcript.message(
        b"threshold",
        &u64::try_from(threshold).unwrap().to_be_bytes(),
    );

    // Spec 1.3
    let f: Polynomial<C> = Polynomial::extend_random(&mut rng, threshold, &s_i);

    // Spec 1.4
    let mut big_f = f.commit();

    // Spec 1.5
    let (my_commitment, my_randomizer) = commit(&mut rng, &big_f);

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
    let my_confirmation = hash(&all_commitments);

    // Spec 2.3
    transcript.message(b"confirmation", my_confirmation.as_ref());

    // Spec 2.4
    let wait1 = chan.next_waitpoint();
    chan.send_many(wait1, &my_confirmation).await;

    // Spec 2.5
    let statement = dlog::Statement::<C> {
        public: &big_f.evaluate_zero(),
    };
    let witness = dlog::Witness::<C> {
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
    chan.send_many(wait2, &(&big_f, &my_randomizer, my_phi_proof))
        .await;

    // Spec 2.7
    let wait3 = chan.next_waitpoint();
    for p in participants.others(me) {
        let x_i_j: ScalarPrimitive<C> = f.evaluate(&p.scalar::<C>()).into();
        chan.send_private(wait3, p, &x_i_j).await;
    }
    let mut x_i = f.evaluate(&me.scalar::<C>());

    // Spec 3.1 + 3.2
    let mut seen = ParticipantCounter::new(&participants);
    seen.put(me);
    while !seen.full() {
        let (from, confirmation): (_, Digest) = chan.recv(wait1).await?;
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
        let (from, (their_big_f, their_randomizer, their_phi_proof)): (
            _,
            (GroupPolynomial<C>, _, _),
        ) = chan.recv(wait2).await?;
        if !seen.put(from) {
            continue;
        }

        if their_big_f.len() != threshold {
            return Err(ProtocolError::AssertionFailed(format!(
                "polynomial from {from:?} has the wrong length"
            )));
        }
        if !all_commitments[from].check(&their_big_f, &their_randomizer) {
            return Err(ProtocolError::AssertionFailed(format!(
                "commitment from {from:?} did not match revealed F"
            )));
        }
        let statement = dlog::Statement::<C> {
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
        let (from, x_j_i): (_, ScalarPrimitive<C>) = chan.recv(wait3).await?;
        if !seen.put(from) {
            continue;
        }
        x_i += C::Scalar::from(x_j_i);
    }

    // Spec 3.7
    if big_f.evaluate(&me.scalar::<C>()) != C::ProjectivePoint::generator() * x_i {
        return Err(ProtocolError::AssertionFailed(
            "received bad private share".to_string(),
        ));
    }

    // Spec 3.8
    let big_x = big_f.evaluate_zero();
    match big_s {
        Some(big_s) if big_s != big_x => {
            return Err(ProtocolError::AssertionFailed(
                "new public key does not match old public key".to_string(),
            ))
        }
        _ => {}
    };

    // Spec 3.9
    Ok((x_i, big_x.into()))
}

/// Represents the output of the key generation protocol.
///
/// This contains our share of the private key, along with the public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenOutput<C: CSCurve> {
    pub private_share: C::Scalar,
    pub public_key: C::AffinePoint,
}

async fn do_keygen<C: CSCurve>(
    chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    threshold: usize,
) -> Result<KeygenOutput<C>, ProtocolError> {
    let s_i = C::Scalar::random(&mut OsRng);
    let (private_share, public_key) =
        do_keyshare::<C>(chan, participants, me, threshold, s_i, None).await?;
    Ok(KeygenOutput {
        private_share,
        public_key,
    })
}

/// The key generation protocol, with a given threshold.
///
/// This produces a new key pair, such that any set of participants
/// of size `>= threshold` can reconstruct the private key,
/// but no smaller set can do the same.
///
/// This needs to be run once, before then being able to perform threshold
/// signatures using the key.
pub fn keygen<C: CSCurve>(
    participants: &[Participant],
    me: Participant,
    threshold: usize,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError> {
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
    Ok(make_protocol(ctx, fut))
}

async fn do_reshare<C: CSCurve>(
    chan: SharedChannel,
    participants: ParticipantList,
    old_subset: ParticipantList,
    me: Participant,
    threshold: usize,
    my_share: Option<C::Scalar>,
    public_key: C::AffinePoint,
) -> Result<C::Scalar, ProtocolError> {
    let s_i = my_share
        .map(|x_i| old_subset.lagrange::<C>(me) * x_i)
        .unwrap_or(C::Scalar::ZERO);
    let big_s: C::ProjectivePoint = public_key.into();
    let (private_share, _) =
        do_keyshare::<C>(chan, participants, me, threshold, s_i, Some(big_s)).await?;
    Ok(private_share)
}

/// The resharing protocol.
///
/// The purpose of this protocol is to take a key generated with one set of participants,
/// and transfer it to another set of participants, potentially with a new threshold.
///
/// Not all participants must be present in the new set, but enough need to be present
/// so that the old key can be reconstructed.
///
/// This protocol creates fresh shares for every party, without revealing the key,
/// of course. The output of the protocol is the new share for this party.
pub fn reshare<C: CSCurve>(
    old_participants: &[Participant],
    old_threshold: usize,
    new_participants: &[Participant],
    new_threshold: usize,
    me: Participant,
    my_share: Option<C::Scalar>,
    public_key: C::AffinePoint,
) -> Result<impl Protocol<Output = C::Scalar>, InitializationError> {
    if new_participants.len() < 2 {
        return Err(InitializationError::BadParameters(format!(
            "participant count cannot be < 2, found: {}",
            new_participants.len()
        )));
    };
    // Spec 1.1
    if new_threshold > new_participants.len() {
        return Err(InitializationError::BadParameters(
            "threshold must be <= participant count".to_string(),
        ));
    }

    let new_participants = ParticipantList::new(new_participants).ok_or_else(|| {
        InitializationError::BadParameters(
            "new participant list cannot contain duplicates".to_string(),
        )
    })?;

    if !new_participants.contains(me) {
        return Err(InitializationError::BadParameters(
            "new participant list must contain this participant".to_string(),
        ));
    }

    let old_participants = ParticipantList::new(old_participants).ok_or_else(|| {
        InitializationError::BadParameters(
            "old participant list cannot contain duplicates".to_string(),
        )
    })?;

    let old_subset = old_participants.intersection(&new_participants);
    if old_subset.len() < old_threshold {
        return Err(InitializationError::BadParameters(
            "not enough old participants to reconstruct private key for resharing".to_string(),
        ));
    }

    if old_subset.contains(me) && my_share.is_none() {
        return Err(InitializationError::BadParameters(
            "this party is present in the old participant list but provided no share".to_string(),
        ));
    }

    let ctx = Context::new();
    let fut = do_reshare::<C>(
        ctx.shared_channel(),
        new_participants,
        old_subset,
        me,
        new_threshold,
        my_share,
        public_key,
    );
    Ok(make_protocol(ctx, fut))
}

/// The refresh protocol.
///
/// This is like resharing, but with extra constraints to ensure that the set
/// of participants and threshold do not change.
pub fn refresh<C: CSCurve>(
    participants: &[Participant],
    threshold: usize,
    me: Participant,
    my_share: C::Scalar,
    public_key: C::AffinePoint,
) -> Result<impl Protocol<Output = C::Scalar>, InitializationError> {
    reshare::<C>(
        participants,
        threshold,
        participants,
        threshold,
        me,
        Some(my_share),
        public_key,
    )
}

#[cfg(test)]
mod test {
    use std::error::Error;

    use k256::{ProjectivePoint, Scalar, Secp256k1};

    use super::*;
    use crate::protocol::{run_protocol, Participant};

    #[allow(clippy::type_complexity)]
    fn do_keygen(
        participants: &[Participant],
        threshold: usize,
    ) -> Result<Vec<(Participant, KeygenOutput<Secp256k1>)>, Box<dyn Error>> {
        let mut protocols: Vec<(
            Participant,
            Box<dyn Protocol<Output = KeygenOutput<Secp256k1>>>,
        )> = Vec::with_capacity(participants.len());

        for p in participants.iter() {
            let protocol = keygen(participants, *p, threshold)?;
            protocols.push((*p, Box::new(protocol)));
        }

        let result = run_protocol(protocols)?;
        Ok(result)
    }

    #[test]
    fn test_keygen() -> Result<(), Box<dyn Error>> {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];
        let threshold = 3;

        let result = do_keygen(&participants, threshold)?;
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
        let x = p_list.lagrange::<Secp256k1>(participants[0]) * shares[0]
            + p_list.lagrange::<Secp256k1>(participants[1]) * shares[1]
            + p_list.lagrange::<Secp256k1>(participants[2]) * shares[2];
        assert_eq!(ProjectivePoint::GENERATOR * x, pub_key);

        Ok(())
    }

    #[test]
    fn test_refresh() -> Result<(), Box<dyn Error>> {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];
        let threshold = 3;

        let result0 = do_keygen(&participants, threshold)?;

        let pub_key = result0[2].1.public_key;

        // Refresh
        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = Scalar>>)> =
            Vec::with_capacity(participants.len());

        for (p, out) in result0.iter() {
            let protocol = refresh::<Secp256k1>(
                &participants,
                threshold,
                *p,
                out.private_share,
                out.public_key,
            )?;
            protocols.push((*p, Box::new(protocol)));
        }

        let result1 = run_protocol(protocols)?;

        let participants = vec![result1[0].0, result1[1].0, result1[2].0];
        let shares = vec![result1[0].1, result1[1].1, result1[2].1];
        let p_list = ParticipantList::new(&participants).unwrap();
        let x = p_list.lagrange::<Secp256k1>(participants[0]) * shares[0]
            + p_list.lagrange::<Secp256k1>(participants[1]) * shares[1]
            + p_list.lagrange::<Secp256k1>(participants[2]) * shares[2];
        assert_eq!(ProjectivePoint::GENERATOR * x, pub_key);

        Ok(())
    }

    #[test]
    fn test_reshare() -> Result<(), Box<dyn Error>> {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
        ];
        let threshold0 = 3;
        let threshold1 = 4;

        let result0 = do_keygen(&participants[..3], threshold0)?;

        let pub_key = result0[2].1.public_key;

        // Reshare
        let mut setup: Vec<_> = result0
            .into_iter()
            .map(|(p, out)| (p, (Some(out.private_share), out.public_key)))
            .collect();
        setup.push((Participant::from(3u32), (None, pub_key)));

        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = Scalar>>)> =
            Vec::with_capacity(participants.len());

        for (p, out) in setup.iter() {
            let protocol = reshare::<Secp256k1>(
                &participants[..3],
                threshold0,
                &participants,
                threshold1,
                *p,
                out.0,
                out.1,
            )?;
            protocols.push((*p, Box::new(protocol)));
        }

        let result1 = run_protocol(protocols)?;

        let participants = vec![result1[0].0, result1[1].0, result1[2].0, result1[3].0];
        let shares = vec![result1[0].1, result1[1].1, result1[2].1, result1[3].1];
        let p_list = ParticipantList::new(&participants).unwrap();
        let x = p_list.lagrange::<Secp256k1>(participants[0]) * shares[0]
            + p_list.lagrange::<Secp256k1>(participants[1]) * shares[1]
            + p_list.lagrange::<Secp256k1>(participants[2]) * shares[2]
            + p_list.lagrange::<Secp256k1>(participants[3]) * shares[3];
        assert_eq!(ProjectivePoint::GENERATOR * x, pub_key);

        Ok(())
    }
}
