use ecdsa::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use magikitten::Transcript;
use rand_core::OsRng;

use crate::{
    crypto::{commit, Commitment},
    math::{GroupPolynomial, Polynomial},
    participants::{ParticipantCounter, ParticipantList, ParticipantMap},
    proofs::{dlog, dlogeq},
    protocol::{
        internal::{make_protocol, Context},
        InitializationError, Participant, Protocol, ProtocolError,
    },
    serde::encode,
};

use super::{multiplication::multiplication, Setup, TriplePub, TripleShare};

/// The output of running the triple generation protocol.
pub type TripleGenerationOutput = (TripleShare, TriplePub);

async fn do_generation(
    ctx: Context<'_>,
    setup: Setup,
    participants: ParticipantList,
    me: Participant,
    threshold: usize,
) -> Result<TripleGenerationOutput, ProtocolError> {
    let mut rng = OsRng;
    let mut chan = ctx.shared_channel();
    let mut transcript = Transcript::new(b"cait-sith v0.1.0 triple generation");

    // Spec 1.1
    transcript.message(b"participants", &encode(&participants));
    // To allow interop between platforms where usize is different
    transcript.message(
        b"threshold",
        &u64::try_from(threshold).unwrap().to_be_bytes(),
    );

    // Spec 1.2
    let e = Polynomial::random(&mut rng, threshold);
    let f = Polynomial::random(&mut rng, threshold);

    // Spec 1.3
    let big_e_i = e.commit();
    let big_f_i = f.commit();

    // Spec 1.4
    let my_commitment = commit(&(&big_e_i, &big_f_i));

    // Spec 1.5
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
    let fut = {
        let ctx = ctx.clone();
        let e0 = e.evaluate_zero();
        let f0 = f.evaluate_zero();
        multiplication(ctx, my_confirmation, me, setup, e0, f0)
    };
    let multiplication_task = ctx.spawn(fut);

    // Spec 2.5
    let wait1 = chan.next_waitpoint();
    chan.send_many(wait1, &my_confirmation).await;

    // Spec 2.6
    let statement = dlog::Statement {
        public: &big_f_i.evaluate_zero(),
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

    // Spec 2.7
    let wait2 = chan.next_waitpoint();
    chan.send_many(wait2, &(&big_e_i, &big_f_i, my_phi_proof))
        .await;

    // Spec 2.8
    let wait3 = chan.next_waitpoint();
    for p in participants.others(me) {
        let a_i_j = e.evaluate(&p.scalar());
        let b_i_j = f.evaluate(&p.scalar());
        chan.send_private(wait3, p, &(a_i_j, b_i_j)).await;
    }
    let mut a_i = e.evaluate(&me.scalar());
    let mut b_i = f.evaluate(&me.scalar());

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

    // Spec 3.3 + 3.4, and also part of 3.6, for summing up the Es and Fs.
    let mut big_e = big_e_i.clone();
    let mut big_f = big_f_i;
    let mut big_e_j_zero = ParticipantMap::new(&participants);
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, (their_big_e, their_big_f, their_phi_proof)): (
            _,
            (GroupPolynomial, GroupPolynomial, _),
        ) = chan.recv(wait2).await?;
        if !seen.put(from) {
            continue;
        }

        if their_big_e.len() != threshold || their_big_f.len() != threshold {
            return Err(ProtocolError::AssertionFailed(format!(
                "polynomial from {from:?} has the wrong length"
            )));
        }
        if commit(&(&their_big_e, &their_big_f)) != all_commitments[from] {
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
        big_e_j_zero.put(from, their_big_e.evaluate_zero());
        big_e += &their_big_e;
        big_f += &their_big_f;
    }

    // Spec 3.5 + 3.6
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, (a_j_i, b_j_i)): (_, (Scalar, Scalar)) = chan.recv(wait3).await?;
        if !seen.put(from) {
            continue;
        }
        a_i += a_j_i;
        b_i += b_j_i
    }

    // Spec 3.7
    if big_e.evaluate(&me.scalar()) != ProjectivePoint::GENERATOR * a_i
        || big_f.evaluate(&me.scalar()) != ProjectivePoint::GENERATOR * b_i
    {
        return Err(ProtocolError::AssertionFailed(
            "received bad private share".to_string(),
        ));
    }

    // Spec 3.8
    let big_c_i = big_f.evaluate_zero() * e.evaluate_zero();

    // Spec 3.9
    let statement = dlogeq::Statement {
        public0: &big_e_i.evaluate_zero(),
        generator1: &big_f.evaluate_zero(),
        public1: &big_c_i,
    };
    let witness = dlogeq::Witness {
        x: &e.evaluate_zero(),
    };
    let my_phi_proof = dlogeq::prove(
        &mut rng,
        &mut transcript.forked(b"dlogeq0", &me.bytes()),
        statement,
        witness,
    );

    // Spec 3.10
    let wait4 = chan.next_waitpoint();
    chan.send_many(wait4, &(&big_c_i.to_affine(), my_phi_proof))
        .await;

    // Spec 4.1 + 4.2 + 4.3
    seen.clear();
    seen.put(me);
    let mut big_c = big_c_i;
    while !seen.full() {
        let (from, (big_c_j, their_phi_proof)): (_, (AffinePoint, _)) = chan.recv(wait4).await?;
        if !seen.put(from) {
            continue;
        }
        let big_c_j = big_c_j.to_curve();

        let statement = dlogeq::Statement {
            public0: &big_e_j_zero[from],
            generator1: &big_f.evaluate_zero(),
            public1: &big_c_j,
        };

        if !dlogeq::verify(
            &mut transcript.forked(b"dlogeq0", &from.bytes()),
            statement,
            &their_phi_proof,
        ) {
            return Err(ProtocolError::AssertionFailed(format!(
                "dlogeq proof from {from:?} failed to verify"
            )));
        }

        big_c += big_c_j;
    }

    // Spec 4.4
    let l0 = ctx.run(multiplication_task).await?;

    // Spec 4.5
    let l = Polynomial::extend_random(&mut rng, threshold, &l0);

    // Spec 4.6
    let mut big_l = l.commit();

    // Spec 4.7
    let statement = dlog::Statement {
        public: &big_l.evaluate_zero(),
    };
    let witness = dlog::Witness {
        x: &l.evaluate_zero(),
    };
    let my_phi_proof = dlog::prove(
        &mut rng,
        &mut transcript.forked(b"dlog1", &me.bytes()),
        statement,
        witness,
    );

    // Spec 4.8
    let wait5 = chan.next_waitpoint();
    chan.send_many(wait5, &(&big_l, my_phi_proof)).await;

    // Spec 4.9
    let wait6 = chan.next_waitpoint();
    for p in participants.others(me) {
        let c_i_j = l.evaluate(&p.scalar());
        chan.send_private(wait6, p, &c_i_j).await;
    }
    let mut c_i = l.evaluate(&me.scalar());

    // Spec 5.1 + 5.2 + 5.3
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, (their_big_l, their_phi_proof)): (_, (GroupPolynomial, _)) =
            chan.recv(wait5).await?;
        if !seen.put(from) {
            continue;
        }

        if their_big_l.len() != threshold {
            return Err(ProtocolError::AssertionFailed(format!(
                "polynomial from {from:?} has the wrong length"
            )));
        }
        let statement = dlog::Statement {
            public: &their_big_l.evaluate_zero(),
        };
        if !dlog::verify(
            &mut transcript.forked(b"dlog1", &from.bytes()),
            statement,
            &their_phi_proof,
        ) {
            return Err(ProtocolError::AssertionFailed(format!(
                "dlog proof from {from:?} failed to verify"
            )));
        }
        big_l += &their_big_l;
    }

    // Spec 5.4
    if big_l.evaluate_zero() != big_c {
        return Err(ProtocolError::AssertionFailed(
            "final polynomial doesn't match C value".to_owned(),
        ));
    }

    // Spec 5.5 + 5.6
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, c_j_i): (_, Scalar) = chan.recv(wait6).await?;
        if !seen.put(from) {
            continue;
        }
        c_i += c_j_i;
    }

    // Spec 5.7
    if big_l.evaluate(&me.scalar()) != ProjectivePoint::GENERATOR * c_i {
        return Err(ProtocolError::AssertionFailed(
            "received bad private share of c".to_string(),
        ));
    }

    let big_a = big_e.evaluate_zero().to_affine();
    let big_b = big_f.evaluate_zero().to_affine();
    let big_c = big_c.to_affine();

    Ok((
        TripleShare {
            a: a_i,
            b: b_i,
            c: c_i,
        },
        TriplePub {
            big_a,
            big_b,
            big_c,
            participants: participants.into(),
            threshold,
        },
    ))
}

pub fn generate_triple(
    participants: &[Participant],
    me: Participant,
    setup: Setup,
    threshold: usize,
) -> Result<impl Protocol<Output = TripleGenerationOutput>, InitializationError> {
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

    if !setup.can_be_used_for(me, &participants) {
        return Err(InitializationError::BadParameters(
            "the triple setup cannot be used with these participants".to_owned(),
        ));
    }

    let ctx = Context::new();
    let fut = do_generation(ctx.clone(), setup, participants, me, threshold);
    Ok(make_protocol(ctx, fut))
}

#[cfg(test)]
mod test {
    use k256::ProjectivePoint;

    use crate::{
        participants::ParticipantList,
        protocol::{run_protocol, Participant, Protocol, ProtocolError},
        triples::{generate_triple, setup, Setup},
    };

    use super::TripleGenerationOutput;

    #[test]
    fn test_triple_generation() -> Result<(), ProtocolError> {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];
        let threshold = 3;

        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = Setup>>)> =
            Vec::with_capacity(participants.len());

        for p in participants.iter() {
            let protocol = setup(&participants, *p);
            assert!(protocol.is_ok());
            let protocol = protocol.unwrap();
            protocols.push((*p, Box::new(protocol)));
        }

        let result = run_protocol(protocols)?;

        let mut protocols: Vec<(
            Participant,
            Box<dyn Protocol<Output = TripleGenerationOutput>>,
        )> = Vec::with_capacity(result.len());

        for (p, setup) in result {
            let protocol = generate_triple(&participants, p, setup, threshold);
            assert!(protocol.is_ok());
            let protocol = protocol.unwrap();
            protocols.push((p, Box::new(protocol)));
        }

        let result = run_protocol(protocols)?;

        assert!(result.len() == participants.len());
        assert_eq!(result[0].1 .1, result[1].1 .1);
        assert_eq!(result[1].1 .1, result[2].1 .1);

        let triple_pub = result[2].1 .1.clone();

        let participants = vec![result[0].0, result[1].0, result[2].0];
        let triple_shares = vec![
            result[0].1 .0.clone(),
            result[1].1 .0.clone(),
            result[2].1 .0.clone(),
        ];
        let p_list = ParticipantList::new(&participants).unwrap();

        let a = p_list.lagrange(participants[0]) * triple_shares[0].a
            + p_list.lagrange(participants[1]) * triple_shares[1].a
            + p_list.lagrange(participants[2]) * triple_shares[2].a;
        assert_eq!(ProjectivePoint::GENERATOR * a, triple_pub.big_a);

        let b = p_list.lagrange(participants[0]) * triple_shares[0].b
            + p_list.lagrange(participants[1]) * triple_shares[1].b
            + p_list.lagrange(participants[2]) * triple_shares[2].b;
        assert_eq!(ProjectivePoint::GENERATOR * b, triple_pub.big_b);

        let c = p_list.lagrange(participants[0]) * triple_shares[0].c
            + p_list.lagrange(participants[1]) * triple_shares[1].c
            + p_list.lagrange(participants[2]) * triple_shares[2].c;
        assert_eq!(ProjectivePoint::GENERATOR * c, triple_pub.big_c);

        assert_eq!(a * b, c);

        Ok(())
    }
}
