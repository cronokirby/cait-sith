use elliptic_curve::{Field, Group, ScalarPrimitive};
use magikitten::Transcript;
use rand_core::OsRng;

use crate::{
    compat::{CSCurve, SerializablePoint},
    crypto::{commit, hash, Digest},
    math::{GroupPolynomial, Polynomial},
    participants::{ParticipantCounter, ParticipantList, ParticipantMap},
    proofs::{dlog, dlogeq},
    protocol::{
        internal::{make_protocol, Context},
        InitializationError, Participant, Protocol, ProtocolError,
    },
    serde::encode,
};

use super::{multiplication::multiplication, TriplePub, TripleShare};

/// The output of running the triple generation protocol.
pub type TripleGenerationOutput<C> = (TripleShare<C>, TriplePub<C>);

const LABEL: &[u8] = b"cait-sith v0.8.0 triple generation";

async fn do_generation<C: CSCurve>(
    ctx: Context<'_>,
    participants: ParticipantList,
    me: Participant,
    threshold: usize,
) -> Result<TripleGenerationOutput<C>, ProtocolError> {
    let mut rng = OsRng;
    let mut chan = ctx.shared_channel();
    let mut transcript = Transcript::new(LABEL);

    // Spec 1.1
    transcript.message(b"group", C::NAME);
    transcript.message(b"participants", &encode(&participants));
    // To allow interop between platforms where usize is different
    transcript.message(
        b"threshold",
        &u64::try_from(threshold).unwrap().to_be_bytes(),
    );

    // Spec 1.2
    let e: Polynomial<C> = Polynomial::random(&mut rng, threshold);
    let f: Polynomial<C> = Polynomial::random(&mut rng, threshold);
    let mut l: Polynomial<C> = Polynomial::random(&mut rng, threshold);

    // Spec 1.3
    l.set_zero(C::Scalar::ZERO);

    // Spec 1.4
    let big_e_i = e.commit();
    let big_f_i = f.commit();
    let big_l_i = l.commit();

    // Spec 1.5
    let (my_commitment, my_randomizer) = commit(&mut rng, &(&big_e_i, &big_f_i, &big_l_i));

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
    let fut = {
        let ctx = ctx.clone();
        let e0 = e.evaluate_zero();
        let f0 = f.evaluate_zero();
        multiplication::<C>(ctx, my_confirmation, participants.clone(), me, e0, f0)
    };
    let multiplication_task = ctx.spawn(fut);

    // Spec 2.5
    let wait1 = chan.next_waitpoint();
    chan.send_many(wait1, &my_confirmation).await;

    // Spec 2.6
    let statement0 = dlog::Statement::<C> {
        public: &big_e_i.evaluate_zero(),
    };
    let witness0 = dlog::Witness::<C> {
        x: &e.evaluate_zero(),
    };
    let my_phi_proof0 = dlog::prove(
        &mut rng,
        &mut transcript.forked(b"dlog0", &me.bytes()),
        statement0,
        witness0,
    );
    let statement1 = dlog::Statement::<C> {
        public: &big_f_i.evaluate_zero(),
    };
    let witness1 = dlog::Witness::<C> {
        x: &f.evaluate_zero(),
    };
    let my_phi_proof1 = dlog::prove(
        &mut rng,
        &mut transcript.forked(b"dlog1", &me.bytes()),
        statement1,
        witness1,
    );

    // Spec 2.7
    let wait2 = chan.next_waitpoint();
    {
        chan.send_many(
            wait2,
            &(
                &big_e_i,
                &big_f_i,
                &big_l_i,
                my_randomizer,
                my_phi_proof0,
                my_phi_proof1,
            ),
        )
        .await;
    }

    // Spec 2.8
    let wait3 = chan.next_waitpoint();
    for p in participants.others(me) {
        let a_i_j: ScalarPrimitive<C> = e.evaluate(&p.scalar::<C>()).into();
        let b_i_j: ScalarPrimitive<C> = f.evaluate(&p.scalar::<C>()).into();
        chan.send_private(wait3, p, &(a_i_j, b_i_j)).await;
    }
    let mut a_i = e.evaluate(&me.scalar::<C>());
    let mut b_i = f.evaluate(&me.scalar::<C>());

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

    // Spec 3.3 + 3.4, and also part of 3.6, 5.3, for summing up the Es, Fs, and Ls.
    let mut big_e = big_e_i.clone();
    let mut big_f = big_f_i;
    let mut big_l = big_l_i;
    let mut big_e_j_zero = ParticipantMap::new(&participants);
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (
            from,
            (
                their_big_e,
                their_big_f,
                their_big_l,
                their_randomizer,
                their_phi_proof0,
                their_phi_proof1,
            ),
        ): (
            _,
            (
                GroupPolynomial<C>,
                GroupPolynomial<C>,
                GroupPolynomial<C>,
                _,
                _,
                _,
            ),
        ) = chan.recv(wait2).await?;
        if !seen.put(from) {
            continue;
        }

        if their_big_e.len() != threshold
            || their_big_f.len() != threshold
            || their_big_l.len() != threshold
        {
            return Err(ProtocolError::AssertionFailed(format!(
                "polynomial from {from:?} has the wrong length"
            )));
        }

        if !bool::from(their_big_l.evaluate_zero().is_identity()) {
            return Err(ProtocolError::AssertionFailed(format!(
                "L(0) from {from:?} is not 0"
            )));
        }

        if !all_commitments[from].check(
            &(&their_big_e, &their_big_f, &their_big_l),
            &their_randomizer,
        ) {
            return Err(ProtocolError::AssertionFailed(format!(
                "commitment from {from:?} did not match revealed F"
            )));
        }

        let statement0 = dlog::Statement::<C> {
            public: &their_big_e.evaluate_zero(),
        };
        if !dlog::verify(
            &mut transcript.forked(b"dlog0", &from.bytes()),
            statement0,
            &their_phi_proof0,
        ) {
            return Err(ProtocolError::AssertionFailed(format!(
                "dlog proof from {from:?} failed to verify"
            )));
        }

        let statement1 = dlog::Statement::<C> {
            public: &their_big_f.evaluate_zero(),
        };
        if !dlog::verify(
            &mut transcript.forked(b"dlog1", &from.bytes()),
            statement1,
            &their_phi_proof1,
        ) {
            return Err(ProtocolError::AssertionFailed(format!(
                "dlog proof from {from:?} failed to verify"
            )));
        }

        big_e_j_zero.put(from, their_big_e.evaluate_zero());
        big_e += &their_big_e;
        big_f += &their_big_f;
        big_l += &their_big_l;
    }

    // Spec 3.5 + 3.6
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, (a_j_i, b_j_i)): (_, (ScalarPrimitive<C>, ScalarPrimitive<C>)) =
            chan.recv(wait3).await?;
        if !seen.put(from) {
            continue;
        }
        a_i += &a_j_i.into();
        b_i += &b_j_i.into();
    }

    // Spec 3.7
    if big_e.evaluate(&me.scalar::<C>()) != C::ProjectivePoint::generator() * a_i
        || big_f.evaluate(&me.scalar::<C>()) != C::ProjectivePoint::generator() * b_i
    {
        return Err(ProtocolError::AssertionFailed(
            "received bad private share".to_string(),
        ));
    }

    // Spec 3.8
    let big_c_i = big_f.evaluate_zero() * e.evaluate_zero();

    // Spec 3.9
    let statement = dlogeq::Statement::<C> {
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
    chan.send_many(
        wait4,
        &(
            SerializablePoint::<C>::from_projective(&big_c_i),
            my_phi_proof,
        ),
    )
    .await;

    // Spec 4.1 + 4.2 + 4.3
    seen.clear();
    seen.put(me);
    let mut big_c = big_c_i;
    while !seen.full() {
        let (from, (big_c_j, their_phi_proof)): (_, (SerializablePoint<C>, _)) =
            chan.recv(wait4).await?;
        if !seen.put(from) {
            continue;
        }
        let big_c_j = big_c_j.to_projective();

        let statement = dlogeq::Statement::<C> {
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
    let hat_big_c_i = C::ProjectivePoint::generator() * l0;

    // Spec 4.6
    let statement = dlog::Statement::<C> {
        public: &hat_big_c_i,
    };
    let witness = dlog::Witness::<C> { x: &l0 };
    let my_phi_proof = dlog::prove(
        &mut rng,
        &mut transcript.forked(b"dlog2", &me.bytes()),
        statement,
        witness,
    );

    // Spec 4.8
    let wait5 = chan.next_waitpoint();
    chan.send_many(
        wait5,
        &(
            SerializablePoint::<C>::from_projective(&hat_big_c_i),
            my_phi_proof,
        ),
    )
    .await;

    // Spec 4.9
    l.set_zero(l0);
    let wait6 = chan.next_waitpoint();
    for p in participants.others(me) {
        let c_i_j: ScalarPrimitive<C> = l.evaluate(&p.scalar::<C>()).into();
        chan.send_private(wait6, p, &c_i_j).await;
    }
    let mut c_i = l.evaluate(&me.scalar::<C>());

    // Spec 5.1 + 5.2 + 5.3
    seen.clear();
    seen.put(me);
    let mut hat_big_c = hat_big_c_i;
    while !seen.full() {
        let (from, (their_hat_big_c, their_phi_proof)): (_, (SerializablePoint<C>, _)) =
            chan.recv(wait5).await?;
        if !seen.put(from) {
            continue;
        }

        let their_hat_big_c = their_hat_big_c.to_projective();
        let statement = dlog::Statement::<C> {
            public: &their_hat_big_c,
        };
        if !dlog::verify(
            &mut transcript.forked(b"dlog2", &from.bytes()),
            statement,
            &their_phi_proof,
        ) {
            return Err(ProtocolError::AssertionFailed(format!(
                "dlog proof from {from:?} failed to verify"
            )));
        }
        hat_big_c += &their_hat_big_c;
    }

    // Spec 5.3
    big_l.set_zero(hat_big_c);

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
        let (from, c_j_i): (_, ScalarPrimitive<C>) = chan.recv(wait6).await?;
        if !seen.put(from) {
            continue;
        }
        c_i += C::Scalar::from(c_j_i);
    }

    // Spec 5.7
    if big_l.evaluate(&me.scalar::<C>()) != C::ProjectivePoint::generator() * c_i {
        return Err(ProtocolError::AssertionFailed(
            "received bad private share of c".to_string(),
        ));
    }

    let big_a = big_e.evaluate_zero().into();
    let big_b = big_f.evaluate_zero().into();
    let big_c = big_c.into();

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

/// Generate a triple through a multi-party protocol.
///
/// This requires a setup phase to have been conducted with these parties
/// previously.
///
/// The resulting triple will be threshold shared, according to the threshold
/// provided to this function.
pub fn generate_triple<C: CSCurve>(
    participants: &[Participant],
    me: Participant,
    threshold: usize,
) -> Result<impl Protocol<Output = TripleGenerationOutput<C>>, InitializationError> {
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

    let ctx = Context::new();
    let fut = do_generation(ctx.clone(), participants, me, threshold);
    Ok(make_protocol(ctx, fut))
}

#[cfg(test)]
mod test {
    use k256::{ProjectivePoint, Secp256k1};

    use crate::{
        participants::ParticipantList,
        protocol::{run_protocol, Participant, Protocol, ProtocolError},
        triples::generate_triple,
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

        #[allow(clippy::type_complexity)]
        let mut protocols: Vec<(
            Participant,
            Box<dyn Protocol<Output = TripleGenerationOutput<Secp256k1>>>,
        )> = Vec::with_capacity(participants.len());

        for &p in &participants {
            let protocol = generate_triple(&participants, p, threshold);
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

        let a = p_list.lagrange::<Secp256k1>(participants[0]) * triple_shares[0].a
            + p_list.lagrange::<Secp256k1>(participants[1]) * triple_shares[1].a
            + p_list.lagrange::<Secp256k1>(participants[2]) * triple_shares[2].a;
        assert_eq!(ProjectivePoint::GENERATOR * a, triple_pub.big_a);

        let b = p_list.lagrange::<Secp256k1>(participants[0]) * triple_shares[0].b
            + p_list.lagrange::<Secp256k1>(participants[1]) * triple_shares[1].b
            + p_list.lagrange::<Secp256k1>(participants[2]) * triple_shares[2].b;
        assert_eq!(ProjectivePoint::GENERATOR * b, triple_pub.big_b);

        let c = p_list.lagrange::<Secp256k1>(participants[0]) * triple_shares[0].c
            + p_list.lagrange::<Secp256k1>(participants[1]) * triple_shares[1].c
            + p_list.lagrange::<Secp256k1>(participants[2]) * triple_shares[2].c;
        assert_eq!(ProjectivePoint::GENERATOR * c, triple_pub.big_c);

        assert_eq!(a * b, c);

        Ok(())
    }
}
