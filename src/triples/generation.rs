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
use crate::crypto::{Commitment, Randomizer};
use crate::triples::multiplication::multiplication_many;

use super::{multiplication::multiplication, TriplePub, TripleShare};

/// The output of running the triple generation protocol.
pub type TripleGenerationOutput<C> = (TripleShare<C>, TriplePub<C>);

pub type TripleGenerationOutputMany<C> = Vec<(TripleShare<C>, TriplePub<C>)>;

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

async fn do_generation_many<C: CSCurve, const N: usize>(
    ctx: Context<'_>,
    participants: ParticipantList,
    me: Participant,
    threshold: usize,
) -> Result<TripleGenerationOutputMany<C>, ProtocolError> {
    assert!(N > 0);
    
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
    
    let mut my_commitments = vec![];
    let mut my_randomizers = vec![];
    let mut e_v = vec![];
    let mut f_v = vec![];
    let mut l_v = vec![];
    let mut big_e_i_v = vec![];
    let mut big_f_i_v = vec![];
    let mut big_l_i_v = vec![];

    for _ in 0..N {
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
        
        my_commitments.push(my_commitment);
        my_randomizers.push(my_randomizer);
        e_v.push(e);
        f_v.push(f);
        l_v.push(l);
        big_e_i_v.push(big_e_i);
        big_f_i_v.push(big_f_i);
        big_l_i_v.push(big_l_i);
    }

    // Spec 1.6
    let wait0 = chan.next_waitpoint();
    chan.send_many(wait0, &my_commitments).await;

    // Spec 2.1
    let mut all_commitments_vec: Vec<ParticipantMap<Commitment>> = vec![];
    for i in 0..N {
        let mut m = ParticipantMap::new(&participants);
        m.put(me, my_commitments[i]);
        all_commitments_vec.push(m);
    }
    
    while all_commitments_vec.iter().any(|all_commitments| !all_commitments.full()) {
        let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
        for i in 0..N {
            all_commitments_vec[i].put(from, commitments[i]);
        }
    }
    
    // Spec 2.2
    let mut my_confirmations = vec![];
    for i in 0..N {
        let all_commitments = &all_commitments_vec[i];
        let my_confirmation = hash(all_commitments);
        my_confirmations.push(my_confirmation);
    }
    
    // Spec 2.3
    transcript.message(b"confirmation", &encode(&my_confirmations));

    // Spec 2.4
    let fut = {
        let ctx = ctx.clone();
        let e0_v: Vec<_> = e_v.iter().map(|e| e.evaluate_zero()).collect();
        let f0_v: Vec<_> = f_v.iter().map(|f| f.evaluate_zero()).collect();
        multiplication_many::<C, N>(ctx, my_confirmations.clone(), participants.clone(), me, e0_v, f0_v)
    };
    let multiplication_task = ctx.spawn(fut);

    // Spec 2.5
    let wait1 = chan.next_waitpoint();
    chan.send_many(wait1, &my_confirmations).await;

    let mut my_phi_proof0v = vec![];
    let mut my_phi_proof1v = vec![];

    for i in 0..N {
        let big_e_i = &big_e_i_v[i];
        let big_f_i = &big_f_i_v[i];
        let e = &e_v[i];
        let f = &f_v[i];
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
        my_phi_proof0v.push(my_phi_proof0);
        my_phi_proof1v.push(my_phi_proof1);
    }
    
    // Spec 2.7
    let wait2 = chan.next_waitpoint();
    {
        chan.send_many(
            wait2,
            &(
                &big_e_i_v,
                &big_f_i_v,
                &big_l_i_v,
                &my_randomizers,
                &my_phi_proof0v,
                &my_phi_proof1v
            ),
        )
        .await;
    }

    // Spec 2.8
    let wait3 = chan.next_waitpoint();
    for p in participants.others(me) {
        let mut a_i_j_v = vec![];
        let mut b_i_j_v = vec![];
        for i in 0..N {
            let e = &e_v[i];
            let f = &f_v[i];
            let a_i_j: ScalarPrimitive<C> = e.evaluate(&p.scalar::<C>()).into();
            let b_i_j: ScalarPrimitive<C> = f.evaluate(&p.scalar::<C>()).into();
            a_i_j_v.push(a_i_j);
            b_i_j_v.push(b_i_j);
        }
        chan.send_private(wait3, p, &(a_i_j_v, b_i_j_v)).await;
    }
    let mut a_i_v = vec![];
    let mut b_i_v = vec![];
    for i in 0..N {
        let e = &e_v[i];
        let f = &f_v[i];
        let a_i = e.evaluate(&me.scalar::<C>());
        let b_i = f.evaluate(&me.scalar::<C>());
        a_i_v.push(a_i);
        b_i_v.push(b_i);
    }

    // Spec 3.1 + 3.2
    let mut seen = ParticipantCounter::new(&participants);
    seen.put(me);
    while !seen.full() {
        let (from, confirmation): (_, Vec<Digest>) = chan.recv(wait1).await?;
        if !seen.put(from) {
            continue;
        }
        if confirmation != my_confirmations {
            return Err(ProtocolError::AssertionFailed(format!(
                "confirmation from {from:?} did not match expectation"
            )));
        }
    }
    
    // Spec 3.3 + 3.4, and also part of 3.6, 5.3, for summing up the Es, Fs, and Ls.
    let mut big_e_v = vec![];
    let mut big_f_v = vec![];
    let mut big_l_v = vec![];
    let mut big_e_j_zero_v = vec![];
    for i in 0..N {
        big_e_v.push(big_e_i_v[i].clone());
        big_f_v.push(big_f_i_v[i].clone());
        big_l_v.push(big_l_i_v[i].clone());
        big_e_j_zero_v.push(ParticipantMap::new(&participants));
    }
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (
            from,
            (
                their_big_e_v,
                their_big_f_v,
                their_big_l_v,
                their_randomizers,
                their_phi_proof0_v,
                their_phi_proof1_v,
            ),
        ): (
            _,
            (
                Vec<GroupPolynomial<C>>,
                Vec<GroupPolynomial<C>>,
                Vec<GroupPolynomial<C>>,
                Vec<Randomizer>,
                Vec<dlog::Proof<C>>,
                Vec<dlog::Proof<C>>,
            ),
        ) = chan.recv(wait2).await?;
        if !seen.put(from) {
            continue;
        }
        
        for i in 0..N {
            let all_commitments = &all_commitments_vec[i];
            let their_big_e = &their_big_e_v[i];
            let their_big_f = &their_big_f_v[i];
            let their_big_l = &their_big_l_v[i];
            let their_randomizer = &their_randomizers[i];
            let their_phi_proof0 = &their_phi_proof0_v[i];
            let their_phi_proof1 = &their_phi_proof1_v[i];
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
    
            big_e_j_zero_v[i].put(from, their_big_e.evaluate_zero());
            
            big_e_v[i] += &their_big_e;
            big_f_v[i] += &their_big_f;
            big_l_v[i] += &their_big_l;
        }
    }

    // Spec 3.5 + 3.6
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, (a_j_i_v, b_j_i_v)): (_, (Vec<ScalarPrimitive<C>>, Vec<ScalarPrimitive<C>>)) =
            chan.recv(wait3).await?;
        if !seen.put(from) {
            continue;
        }
        for i in 0..N {
            let a_j_i = &a_j_i_v[i];
            let b_j_i = &b_j_i_v[i];
            a_i_v[i] += &(*a_j_i).into();
            b_i_v[i] += &(*b_j_i).into();
        }
    }

    let mut big_c_i_points = vec![];
    let mut big_c_i_v = vec![];
    let mut my_phi_proofs = vec![];
    for i in 0..N {
        let big_e = &big_e_v[i];
        let big_f = &big_f_v[i];
        let a_i = &a_i_v[i];
        let b_i = &b_i_v[i];
        let e = &e_v[i];
        // Spec 3.7
        let check1 = big_e.evaluate(&me.scalar::<C>()) != C::ProjectivePoint::generator() * a_i;
        let check2 = big_f.evaluate(&me.scalar::<C>()) != C::ProjectivePoint::generator() * b_i;
        if check1 || check2 {
            return Err(ProtocolError::AssertionFailed(
                "received bad private share".to_string(),
            ));
        }
        // Spec 3.8
        let big_c_i = big_f.evaluate_zero() * e.evaluate_zero();
        let big_e_i = &big_e_i_v[i];
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
        big_c_i_points.push(SerializablePoint::<C>::from_projective(&big_c_i));
        big_c_i_v.push(big_c_i);
        my_phi_proofs.push(my_phi_proof);
    }

    // Spec 3.10
    let wait4 = chan.next_waitpoint();
    chan.send_many(
        wait4,
        &(
            &big_c_i_points,
            &my_phi_proofs,
        ),
    )
    .await;

    // Spec 4.1 + 4.2 + 4.3
    seen.clear();
    seen.put(me);
    let mut big_c_v = vec![];
    for i in 0..N {
        big_c_v.push(big_c_i_v[i]);
    }
    while !seen.full() {
        let (from, (big_c_j_v, their_phi_proofs)): (_, (Vec<SerializablePoint<C>>, Vec<dlogeq::Proof<C>>)) =
            chan.recv(wait4).await?;
        if !seen.put(from) {
            continue;
        }
        for i in 0..N {
            let big_e_j_zero = &big_e_j_zero_v[i];
            let big_f = &big_f_v[i];

            let big_c_j = big_c_j_v[i].to_projective();
            let their_phi_proof = &their_phi_proofs[i];
    
            let statement = dlogeq::Statement::<C> {
                public0: &big_e_j_zero[from],
                generator1: &big_f.evaluate_zero(),
                public1: &big_c_j,
            };
    
            if !dlogeq::verify(
                &mut transcript.forked(b"dlogeq0", &from.bytes()),
                statement,
                their_phi_proof,
            ) {
                return Err(ProtocolError::AssertionFailed(format!(
                    "dlogeq proof from {from:?} failed to verify"
                )));
            }
            big_c_v[i] += big_c_j;
        }
    }

    // Spec 4.4
    let l0_v = ctx.run(multiplication_task).await?;

    let mut hat_big_c_i_points = vec![];
    let mut hat_big_c_i_v = vec![];
    let mut my_phi_proofs = vec![];
    for i in 0..N {
        // Spec 4.5
        let l0 = l0_v[i];
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
        hat_big_c_i_points.push(SerializablePoint::<C>::from_projective(&hat_big_c_i));
        hat_big_c_i_v.push(hat_big_c_i);
        my_phi_proofs.push(my_phi_proof);
    }
    
    // Spec 4.8
    let wait5 = chan.next_waitpoint();
    chan.send_many(
        wait5,
        &(
            &hat_big_c_i_points,
            &my_phi_proofs,
        ),
    )
    .await;
    
    // Spec 4.9
    for i in 0..N {
        let l = &mut l_v[i];
        let l0 = &l0_v[i];
        l.set_zero(*l0);
    }
    let wait6 = chan.next_waitpoint();
    let mut c_i_v = vec![];
    for p in participants.others(me) {
        let mut c_i_j_v = Vec::new();
        for i in 0..N {
            let l = &mut l_v[i];
            let c_i_j: ScalarPrimitive<C> = l.evaluate(&p.scalar::<C>()).into();
            c_i_j_v.push(c_i_j);
        }
        chan.send_private(wait6, p, &c_i_j_v).await;
    }
    for i in 0..N {
        let l = &mut l_v[i];
        let c_i = l.evaluate(&me.scalar::<C>());
        c_i_v.push(c_i);
    }
    
    // Spec 5.1 + 5.2 + 5.3
    seen.clear();
    seen.put(me);
    let mut hat_big_c_v = vec![];
    for i in 0..N {
        hat_big_c_v.push(hat_big_c_i_v[i]);
    }
    
    while !seen.full() {
        let (from, (their_hat_big_c_i_points, their_phi_proofs)): (_, (Vec<SerializablePoint<C>>, Vec<dlog::Proof<C>>)) =
            chan.recv(wait5).await?;
        if !seen.put(from) {
            continue;
        }
        for i in 0..N {
            let their_hat_big_c = their_hat_big_c_i_points[i].to_projective();
            let their_phi_proof = &their_phi_proofs[i];
            
            let statement = dlog::Statement::<C> {
                public: &their_hat_big_c,
            };
            if !dlog::verify(
                &mut transcript.forked(b"dlog2", &from.bytes()),
                statement,
                their_phi_proof,
            ) {
                return Err(ProtocolError::AssertionFailed(format!(
                    "dlog proof from {from:?} failed to verify"
                )));
            }
            hat_big_c_v[i] += &their_hat_big_c;
        }
    }

    
    for i in 0..N {
        let big_l = &mut big_l_v[i];
        let hat_big_c = &hat_big_c_v[i];
        let big_c = &big_c_v[i];
        
        // Spec 5.3
        big_l.set_zero(*hat_big_c);
        
        // Spec 5.4
        if big_l.evaluate_zero() != *big_c {
            return Err(ProtocolError::AssertionFailed(
                "final polynomial doesn't match C value".to_owned(),
            ));
        }
    }
    
    // Spec 5.5 + 5.6
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, c_j_i_v): (_, Vec<ScalarPrimitive<C>>) = chan.recv(wait6).await?;
        if !seen.put(from) {
            continue;
        }
        for i in 0..N {
            let c_j_i = c_j_i_v[i];
            c_i_v[i] += C::Scalar::from(c_j_i);
        }
    }

    let mut ret = vec![];
    // Spec 5.7
    for i in 0..N {
        let big_l = &big_l_v[i];
        let c_i = &c_i_v[i];
        let a_i = &a_i_v[i];
        let b_i = &b_i_v[i];
        let big_e = &big_e_v[i];
        let big_f = &big_f_v[i];
        let big_c = &big_c_v[i];
        
        if big_l.evaluate(&me.scalar::<C>()) != C::ProjectivePoint::generator() * c_i {
            return Err(ProtocolError::AssertionFailed(
                "received bad private share of c".to_string(),
            ));
        }
        let big_a = big_e.evaluate_zero().into();
        let big_b = big_f.evaluate_zero().into();
        let big_c = (*big_c).into();

        ret.push((
            TripleShare {
                a: *a_i,
                b: *b_i,
                c: *c_i,
            },
            TriplePub {
                big_a,
                big_b,
                big_c,
                participants: participants.clone().into(),
                threshold,
            },
        ))
    }

    Ok(ret)
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

/// As [`generate_triple`] but for many triples at once
pub fn generate_triple_many<C: CSCurve, const N: usize>(
    participants: &[Participant],
    me: Participant,
    threshold: usize,
) -> Result<impl Protocol<Output = TripleGenerationOutputMany<C>>, InitializationError> {
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
    let fut = do_generation_many::<C, N>(ctx.clone(), participants, me, threshold);
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

    use super::{generate_triple_many, TripleGenerationOutput, TripleGenerationOutputMany};

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
    
    #[test]
    fn test_triple_generation_many() -> Result<(), ProtocolError> {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];
        let threshold = 3;

        #[allow(clippy::type_complexity)]
        let mut protocols: Vec<(
            Participant,
            Box<dyn Protocol<Output = TripleGenerationOutputMany<Secp256k1>>>,
        )> = Vec::with_capacity(participants.len());

        for &p in &participants {
            let protocol = generate_triple_many::<Secp256k1, 1>(&participants, p, threshold);
            assert!(protocol.is_ok());
            let protocol = protocol.unwrap();
            protocols.push((p, Box::new(protocol)));
        }

        let result = run_protocol(protocols)?;

        assert!(result.len() == participants.len());
        assert_eq!(result[0].1[0].1, result[1].1[0].1);
        assert_eq!(result[1].1[0].1, result[2].1[0].1);

        let triple_pub = result[2].1[0].1.clone();

        let participants = vec![result[0].0, result[1].0, result[2].0];
        let triple_shares = vec![
            result[0].1[0].0.clone(),
            result[1].1[0].0.clone(),
            result[2].1[0].0.clone(),
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
