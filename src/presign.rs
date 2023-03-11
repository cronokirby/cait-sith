use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::{AffinePoint, ProjectivePoint, Scalar, Secp256k1};
use rand_core::OsRng;

use crate::math::{GroupPolynomial, Polynomial};
use crate::participants::ParticipantCounter;
use crate::protocol::internal::{make_protocol, Context, SharedChannel};
use crate::protocol::{InitializationError, Protocol};
use crate::triples::{TriplePub, TripleShare};
use crate::KeygenOutput;
use crate::{
    participants::ParticipantList,
    protocol::{Participant, ProtocolError},
};

/// The output of the presigning protocol.
///
/// This output is basically all the parts of the signature that we can perform
/// without knowing the message.
#[derive(Debug, Clone)]
pub struct PresignOutput {
    /// The public nonce commitment.
    pub big_r: AffinePoint,
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
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    args: PresignArguments,
) -> Result<PresignOutput, ProtocolError> {
    let mut rng = OsRng;

    // Spec 1.2 + 1.3
    let big_k = args.triple0.1.big_a.to_curve();
    let big_d = args.triple0.1.big_b;
    let big_kd = args.triple0.1.big_c;

    let big_x = args.keygen_out.public_key.to_curve();

    let big_a = args.triple1.1.big_a.to_curve();
    let big_b = args.triple1.1.big_b.to_curve();

    let lambda = participants.lagrange(me);

    let k_i = args.triple0.0.a;
    let k_prime_i = lambda * k_i;
    let kd_i = lambda * args.triple0.0.c;

    let a_i = args.triple1.0.a;
    let b_i = args.triple1.0.b;
    let c_i = args.triple1.0.c;
    let a_prime_i = lambda * a_i;
    let b_prime_i = lambda * b_i;

    let x_prime_i = lambda * args.keygen_out.private_share;

    // Spec 1.4
    let f = Polynomial::extend_random(&mut rng, args.threshold, &x_prime_i);

    // Spec 1.5
    let big_f_i = f.commit();

    // Spec 1.6
    let wait0 = chan.next_waitpoint();
    chan.send_many(wait0, &big_f_i).await;

    // Spec 1.7
    let wait1 = chan.next_waitpoint();
    for p in participants.others(me) {
        let x_i_j = f.evaluate(&p.scalar());
        chan.send_private(wait1, p, &x_i_j).await;
    }
    let mut x_i = f.evaluate(&me.scalar());

    // Spec 1.8
    let wait2 = chan.next_waitpoint();
    chan.send_many(wait2, &kd_i).await;

    // Spec 1.9
    let ka_i = k_prime_i + a_prime_i;
    let xb_i = x_prime_i + b_prime_i;

    // Spec 1.10
    let wait3 = chan.next_waitpoint();
    chan.send_many(wait3, &(ka_i, xb_i)).await;

    // Spec 2.1, 2.2, along with the summation of F from 2.4
    let mut big_f = big_f_i;
    let mut seen = ParticipantCounter::new(&participants);
    seen.put(me);
    while !seen.full() {
        let (from, big_f_j): (_, GroupPolynomial<Secp256k1>) = chan.recv(wait0).await?;
        if !seen.put(from) {
            continue;
        }
        if big_f_j.len() != args.threshold {
            return Err(ProtocolError::AssertionFailed(format!(
                "polynomial from {from:?} has the wrong length"
            )));
        }
        big_f += &big_f_j;
    }

    // Spec 2.3, along with the summation of x_i from 2.4
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, x_j_i): (_, Scalar) = chan.recv(wait1).await?;
        if !seen.put(from) {
            continue;
        }
        x_i += x_j_i;
    }

    // Spec 2.5
    if big_f.evaluate_zero() != big_x {
        return Err(ProtocolError::AssertionFailed(
            "polynomial was not a valid resharing of the private key".to_string(),
        ));
    }
    if big_f.evaluate(&me.scalar()) != ProjectivePoint::GENERATOR * x_i {
        return Err(ProtocolError::AssertionFailed(
            "received bad private share of x".to_string(),
        ));
    }

    // Spec 2.6 and 2.7
    let mut kd = kd_i;
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, kd_j): (_, Scalar) = chan.recv(wait2).await?;
        if !seen.put(from) {
            continue;
        }
        kd += kd_j;
    }

    // Spec 2.8
    if big_kd != ProjectivePoint::GENERATOR * kd {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of kd".to_string(),
        ));
    }

    // Spec 2.9 and 2.10
    let mut ka = ka_i;
    let mut xb = xb_i;
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, (ka_j, xb_j)): (_, (Scalar, Scalar)) = chan.recv(wait3).await?;
        if !seen.put(from) {
            continue;
        }
        ka += ka_j;
        xb += xb_j;
    }

    // Spec 2.11
    if (ProjectivePoint::GENERATOR * ka != big_k + big_a)
        || (ProjectivePoint::GENERATOR * xb != big_x + big_b)
    {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of additive triple phase.".to_string(),
        ));
    }

    // Spec 2.12
    let kd_inv = Into::<Option<Scalar>>::into(kd.invert())
        .ok_or_else(|| ProtocolError::AssertionFailed("failed to invert kd".to_string()))?;
    let big_r = (big_d * kd_inv).to_affine();

    // Spec 2.13
    let sigma_i = ka * x_i - xb * a_i + c_i;

    Ok(PresignOutput {
        big_r,
        k: k_i,
        sigma: sigma_i,
    })
}

/// The presignature protocol.
///
/// This is the first phase of performing a signature, in which we perform
/// all the work we can do without yet knowing the message to be signed.
///
/// This work does depend on the private key though, and it's crucial
/// that a presignature is never used.
pub fn presign(
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
    if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
        return Err(InitializationError::BadParameters(
            "New threshold must match the threshold of both triples".to_string(),
        ));
    }

    let participants = ParticipantList::new(participants).ok_or_else(|| {
        InitializationError::BadParameters("participant list cannot contain duplicates".to_string())
    })?;

    let ctx = Context::new();
    let fut = do_presign(ctx.shared_channel(), participants, me, args);
    Ok(make_protocol(ctx, fut))
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;

    use crate::{protocol::run_protocol, triples};

    #[test]
    fn test_presign() {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
        ];
        let original_threshold = 2;
        let f = Polynomial::<Secp256k1>::random(&mut OsRng, original_threshold);
        let big_x = (ProjectivePoint::GENERATOR * f.evaluate_zero()).to_affine();
        let threshold = 2;

        let (triple0_pub, triple0_shares) =
            triples::deal(&mut OsRng, &participants, original_threshold);
        let (triple1_pub, triple1_shares) =
            triples::deal(&mut OsRng, &participants, original_threshold);

        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)> =
            Vec::with_capacity(participants.len());

        for ((p, triple0), triple1) in participants
            .iter()
            .take(3)
            .zip(triple0_shares.into_iter())
            .zip(triple1_shares.into_iter())
        {
            let protocol = presign(
                &participants[..3],
                *p,
                PresignArguments {
                    original_threshold,
                    triple0: (triple0, triple0_pub.clone()),
                    triple1: (triple1, triple1_pub.clone()),
                    keygen_out: KeygenOutput {
                        private_share: f.evaluate(&p.scalar()),
                        public_key: big_x,
                    },
                    threshold,
                },
            );
            assert!(protocol.is_ok());
            let protocol = protocol.unwrap();
            protocols.push((*p, Box::new(protocol)));
        }

        let result = run_protocol(protocols);
        assert!(result.is_ok());
        let result = result.unwrap();

        assert!(result.len() == 3);
        assert_eq!(result[0].1.big_r, result[1].1.big_r);
        assert_eq!(result[1].1.big_r, result[2].1.big_r);

        let big_k = result[2].1.big_r;

        let participants = vec![result[0].0, result[1].0];
        let k_shares = vec![result[0].1.k, result[1].1.k];
        let sigma_shares = vec![result[0].1.sigma, result[1].1.sigma];
        let p_list = ParticipantList::new(&participants).unwrap();
        let k = p_list.lagrange(participants[0]) * k_shares[0]
            + p_list.lagrange(participants[1]) * k_shares[1];
        assert_eq!(ProjectivePoint::GENERATOR * k.invert().unwrap(), big_k);
        let sigma = p_list.lagrange(participants[0]) * sigma_shares[0]
            + p_list.lagrange(participants[1]) * sigma_shares[1];
        assert_eq!(sigma, k * f.evaluate_zero());
    }
}
