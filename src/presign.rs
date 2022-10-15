use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::AffineXCoordinate;
use k256::{AffinePoint, ProjectivePoint, Scalar, U256};
use magikitten::Transcript;
use rand_core::CryptoRngCore;

use crate::crypto::{commit, Commitment};
use crate::math::{GroupPolynomial, Polynomial};
use crate::participants::{ParticipantCounter, ParticipantMap};
use crate::proofs::dlog;
use crate::protocol::internal::Executor;
use crate::protocol::{InitializationError, Protocol};
use crate::serde::encode;
use crate::triples::{TriplePub, TripleShare};
use crate::KeygenOutput;
use crate::{
    participants::ParticipantList,
    protocol::{internal::Communication, Participant, ProtocolError},
};

/// The output of a presignature
#[derive(Debug, Clone)]
pub struct PresignOutput {
    /// The public nonce commitment.
    pub big_k: AffinePoint,
    /// Our share of the nonce value.
    pub k: Scalar,
    /// Our share of the sigma value.
    pub sigma: Scalar,
}

/// The arguments needed to create a presignature.
#[derive(Debug, Clone)]
pub struct PresignArguments {
    /// The original threshold used for the shares of the secret key.
    pub original_threshold: usize,
    /// The first triple's public information, and our share.
    pub triple0: (TripleShare, TriplePub),
    /// Ditto, for the second triple.
    pub triple1: (TripleShare, TriplePub),
    /// The output of key generation, i.e. our share of the secret key, and the public key.
    pub keygen_out: KeygenOutput,
    /// The desired threshold for the presignature.
    pub threshold: usize,
}

async fn do_presign(
    mut rng: impl CryptoRngCore,
    comms: Communication,
    participants: ParticipantList,
    me: Participant,
    args: PresignArguments,
) -> Result<PresignOutput, ProtocolError> {
    let mut transcript = Transcript::new(b"cait-sith v0.1.0 presign");

    let big_x = args.keygen_out.public_key.to_curve();

    let big_a0 = args.triple0.1.big_a;
    let big_b0 = args.triple0.1.big_b;
    let big_c0 = args.triple0.1.big_c;
    let big_a1 = args.triple1.1.big_a;
    let big_b1 = args.triple1.1.big_b;
    let big_c1 = args.triple1.1.big_c;

    // Spec 1.2
    transcript.message(
        b"original threshold",
        &u64::try_from(args.original_threshold)
            .unwrap()
            .to_be_bytes(),
    );
    // Deviate slightly from the spec to make encoding the triples easier.
    transcript.message(b"triple0 public", &encode(&args.triple0.1));
    transcript.message(b"triple1 public", &encode(&args.triple1.1));
    transcript.message(b"participants", &encode(&participants));
    transcript.message(
        b"threshold",
        &u64::try_from(args.threshold).unwrap().to_be_bytes(),
    );

    // Spec 1.3
    let lambda = participants.lagrange(me);
    let x_i = lambda * args.keygen_out.private_share;

    // Spec 1.4
    let a0_i = lambda * args.triple0.0.a;
    let b0_i = lambda * args.triple0.0.b;
    let c0_i = lambda * args.triple0.0.c;
    let a1_i = lambda * args.triple1.0.a;
    let b1_i = lambda * args.triple1.0.b;
    let c1_i = lambda * args.triple1.0.c;

    // Spec 1.5
    let f = Polynomial::random(&mut rng, args.threshold);

    // Spec 1.6
    let big_f_i = f.commit();

    // Spec 1.7
    let d_i = Scalar::generate_biased(&mut rng);
    let big_d_i = AffinePoint::GENERATOR * d_i;

    // Spec 1.8
    let com_i = commit(&(&big_f_i, big_d_i.to_affine()));

    // Spec 1.9
    let wait0 = comms.next_waitpoint();
    comms.send_many(wait0, &com_i).await;

    // Spec 2.1
    let mut all_commitments = ParticipantMap::new(&participants);
    all_commitments.put(me, com_i);
    while !all_commitments.full() {
        let (from, commitment) = comms.recv(wait0).await?;
        all_commitments.put(from, commitment);
    }

    // Spec 2.2
    let my_confirmation = commit(&all_commitments);

    // Spec 2.3
    transcript.message(b"confirmation", my_confirmation.as_ref());

    // Spec 2.4
    let wait1 = comms.next_waitpoint();
    comms.send_many(wait1, &my_confirmation).await;

    // Spec 2.5
    let pi_i = dlog::prove(
        &mut rng,
        &mut transcript.forked(b"dlog0", &me.bytes()),
        dlog::Statement {
            public: &big_f_i.evaluate_zero(),
        },
        dlog::Witness {
            x: &f.evaluate_zero(),
        },
    );
    let pi_prime_i = dlog::prove(
        &mut rng,
        &mut transcript.forked(b"dlog1", &me.bytes()),
        dlog::Statement { public: &big_d_i },
        dlog::Witness { x: &d_i },
    );

    // Spec 2.6
    let wait2 = comms.next_waitpoint();
    comms
        .send_many(wait2, &(&big_f_i, pi_i, big_d_i.to_affine(), pi_prime_i))
        .await;

    // Spec 2.7
    let wait3 = comms.next_waitpoint();
    for p in participants.others(me) {
        let k_i_j = f.evaluate(&p.scalar());
        comms.send_private(wait3, p, &k_i_j).await;
    }
    let mut k_i = f.evaluate(&me.scalar());

    // Spec 2.8
    let ka_i = f.evaluate_zero() + a0_i;
    let db_i = d_i + b0_i;
    let xa_i = x_i + a1_i;
    let kb_i = f.evaluate_zero() + b1_i;

    // Spec 2.9
    let wait4 = comms.next_waitpoint();
    comms.send_many(wait4, &(ka_i, db_i, xa_i, kb_i)).await;

    // Spec 3.1 + 3.2
    let mut seen = ParticipantCounter::new(&participants);
    seen.put(me);
    while !seen.full() {
        let (from, confirmation): (_, Commitment) = comms.recv(wait1).await?;
        if !seen.put(from) {
            continue;
        }
        if confirmation != my_confirmation {
            return Err(ProtocolError::AssertionFailed(format!(
                "confirmation from {from:?} did not match expectation"
            )));
        }
    }

    let mut big_f = big_f_i;
    let mut big_d = big_d_i;

    // Spec 3.3 + 3.4, and summing for 3.6 and D of 3.10
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, (big_f_j, pi_j, big_d_j, pi_prime_j)): (
            _,
            (GroupPolynomial, _, AffinePoint, _),
        ) = comms.recv(wait2).await?;
        if !seen.put(from) {
            continue;
        }

        if big_f_j.len() != args.threshold {
            return Err(ProtocolError::AssertionFailed(format!(
                "polynomial from {from:?} has the wrong length"
            )));
        }

        let com_j = commit(&(&big_f_j, big_d_j));
        if com_j != all_commitments[from] {
            return Err(ProtocolError::AssertionFailed(format!(
                "commitment from {from:?} did not match revealed F_j and D_j"
            )));
        }

        let big_d_j = big_d_j.to_curve();
        if !dlog::verify(
            &mut transcript.forked(b"dlog0", &from.bytes()),
            dlog::Statement {
                public: &big_f_j.evaluate_zero(),
            },
            &pi_j,
        ) {
            return Err(ProtocolError::AssertionFailed(format!(
                "dlog proof from {from:?} failed to verify"
            )));
        }
        if !dlog::verify(
            &mut transcript.forked(b"dlog1", &from.bytes()),
            dlog::Statement { public: &big_d_j },
            &pi_prime_j,
        ) {
            return Err(ProtocolError::AssertionFailed(format!(
                "dlog proof from {from:?} failed to verify"
            )));
        }
        big_f += big_f_j;
        big_d += big_d_j;
    }

    // Spec 3.5 + 3.6
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, k_i_j): (_, Scalar) = comms.recv(wait3).await?;
        if !seen.put(from) {
            continue;
        }
        k_i += k_i_j;
    }

    // Spec 3.7
    if big_f.evaluate(&me.scalar()) != ProjectivePoint::GENERATOR * k_i {
        return Err(ProtocolError::AssertionFailed(
            "received bad private share of k".to_string(),
        ));
    }

    // Spec 3.8
    let big_k = big_f.evaluate_zero();

    // Spec 3.9
    let mut ka = ka_i;
    let mut db = db_i;
    let mut xa = xa_i;
    let mut kb = kb_i;

    // Spec 3.10
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, (ka_j, db_j, xa_j, kb_j)): (_, (Scalar, Scalar, Scalar, Scalar)) =
            comms.recv(wait4).await?;
        if !seen.put(from) {
            continue;
        }
        ka += ka_j;
        db += db_j;
        xa += xa_j;
        kb += kb_j;
    }

    // Spec 3.11
    if (ProjectivePoint::GENERATOR * ka != big_k + big_a0)
        || (ProjectivePoint::GENERATOR * db != big_d + big_b0)
        || (ProjectivePoint::GENERATOR * xa != big_x + big_a1)
        || (ProjectivePoint::GENERATOR * kb != big_k + big_b1)
    {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of additive triple phase.".to_string(),
        ));
    }

    // Spec 3.12
    let kd_i = ka * d_i - db * a0_i + c0_i;
    let l0 = xa * f.evaluate_zero() - kb * a1_i + c1_i;

    // Spec 3.13
    let wait5 = comms.next_waitpoint();
    comms.send_many(wait5, &kd_i).await;

    // Spec 3.14
    let l = Polynomial::extend_random(&mut rng, args.threshold, &l0);

    // Spec 3.15
    let big_l_i = l.commit();

    // Spec 3.16
    let pi_i = dlog::prove(
        &mut rng,
        &mut transcript.forked(b"dlog2", &me.bytes()),
        dlog::Statement {
            public: &big_l_i.evaluate_zero(),
        },
        dlog::Witness {
            x: &l.evaluate_zero(),
        },
    );

    // Spec 3.17
    let wait6 = comms.next_waitpoint();
    comms.send_many(wait6, &(&big_l_i, pi_i)).await;

    // Spec 3.18
    let wait7 = comms.next_waitpoint();
    for p in participants.others(me) {
        let kx_i_j = f.evaluate(&p.scalar());
        comms.send_private(wait7, p, &kx_i_j).await;
    }
    let kx_i_i = f.evaluate(&me.scalar());

    // Spec 4.1 + 4.2
    let mut kd = kd_i;
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, kd_j): (_, Scalar) = comms.recv(wait5).await?;
        if !seen.put(from) {
            continue;
        }
        kd += kd_j;
    }

    // Spec 4.3
    if ProjectivePoint::GENERATOR * kd != big_d * ka - big_a0 * db + big_c0 {
        return Err(ProtocolError::AssertionFailed(
            "kd is not k * d".to_string(),
        ));
    }

    // Spec 4.4 + 4.5, and the summation of L from 4.7
    seen.clear();
    seen.put(me);
    let mut big_l = big_l_i;
    while !seen.full() {
        let (from, (big_l_j, pi_j)): (_, (GroupPolynomial, dlog::Proof)) =
            comms.recv(wait6).await?;
        if !seen.put(from) {
            continue;
        }
        if big_l_j.len() != args.threshold {
            return Err(ProtocolError::AssertionFailed(format!(
                "polynomial from {from:?} has the wrong length"
            )));
        }
        if !dlog::verify(
            &mut transcript.forked(b"dlog2", &from.bytes()),
            dlog::Statement {
                public: &big_l_j.evaluate_zero(),
            },
            &pi_j,
        ) {
            return Err(ProtocolError::AssertionFailed(format!(
                "dlog proof from {from:?} failed to verify"
            )));
        }
        big_l += big_l_j;
    }

    // Spec 4.6 + 4.7
    seen.clear();
    seen.put(me);
    let mut kx_i = kx_i_i;
    while !seen.full() {
        let (from, kx_i_j): (_, Scalar) = comms.recv(wait7).await?;
        if !seen.put(from) {
            continue;
        }
        kx_i += kx_i_j;
    }

    // Spec 4.8
    if big_l.evaluate(&me.scalar()) != ProjectivePoint::GENERATOR * kx_i {
        return Err(ProtocolError::AssertionFailed(
            "received bad private share of kx".to_string(),
        ));
    }

    // Spec 4.9
    if big_l.evaluate_zero() != big_k * xa - big_a1 * kb + big_c1 {
        return Err(ProtocolError::AssertionFailed(
            "kx is not k * x".to_string(),
        ));
    }

    // Spec 4.10
    let big_k = match Option::<Scalar>::from(kd.invert()) {
        Some(r) => (big_k * r).to_affine(),
        None => {
            return Err(ProtocolError::AssertionFailed(
                "kd is not invertible".to_string(),
            ))
        }
    };

    // Spec 4.11
    let r = <Scalar as Reduce<U256>>::from_be_bytes_reduced(big_k.x());
    let sigma_i = r * kx_i;

    Ok(PresignOutput {
        big_k,
        k: k_i,
        sigma: sigma_i,
    })
}

pub fn presign(
    rng: impl CryptoRngCore,
    participants: &[Participant],
    me: Participant,
    args: PresignArguments,
) -> Result<impl Protocol<Output = PresignOutput>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::BadParameters(format!(
            "participant count cannot be < 2, found: {}",
            participants.len()
        )));
    };
    // Spec 1.1
    if args.threshold > participants.len() {
        return Err(InitializationError::BadParameters(
            "threshold must be <= participant count".to_string(),
        ));
    }
    if args.threshold < args.original_threshold {
        return Err(InitializationError::BadParameters(
            "threshold cannot be less than the original threshold".to_string(),
        ));
    }
    // NOTE: We omit the check that the new participant set was present for
    // the triple generation, because presumably they need to have been present
    // in order to have shares.

    // Also check that we have enough participants to reconstruct shares.
    if participants.len() < args.triple0.1.threshold.max(args.triple1.1.threshold) {
        return Err(InitializationError::BadParameters(
            "not enough participants to reconstruct triple values".to_string(),
        ));
    }

    let participants = ParticipantList::new(participants).ok_or_else(|| {
        InitializationError::BadParameters("participant list cannot contain duplicates".to_string())
    })?;

    let comms = Communication::new(participants.len());
    let fut = do_presign(rng, comms.clone(), participants, me, args);
    Ok(Executor::new(comms, fut))
}
