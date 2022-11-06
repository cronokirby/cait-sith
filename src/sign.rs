use ecdsa::signature::Verifier;
use k256::{
    ecdsa::{Signature, VerifyingKey},
    AffinePoint, PublicKey, Scalar,
};

use crate::{
    compat,
    participants::{ParticipantCounter, ParticipantList},
    protocol::{
        internal2::{Context, SharedChannel, run_protocol},
        InitializationError, Participant, Protocol, ProtocolError,
    },
    PresignOutput,
};

/// Represents a signature with extra information, to support different variants of ECDSA.
///
/// An ECDSA signature is usually two scalars. The first scalar is derived from
/// a point on the curve, and because this process is lossy, some other variants
/// of ECDSA also include some extra information in order to recover this point.
///
/// Furthermore, some signature formats may disagree on how precisely to serialize
/// different values as bytes.
///
/// To support these variants, this simply gives you a normal signature, along with the entire
/// first point.
#[derive(Debug, Clone)]
pub struct FullSignature {
    /// This is the entire first point.
    pub big_k: AffinePoint,
    /// This is the usual signature.
    pub sig: Signature,
}

async fn do_sign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    public_key: PublicKey,
    presignature: PresignOutput,
    msg: Vec<u8>,
) -> Result<FullSignature, ProtocolError> {
    // Spec 1.1
    let lambda = participants.lagrange(me);
    let k_i = lambda * presignature.k;

    // Spec 1.2
    let sigma_i = lambda * presignature.sigma;

    // Spec 1.3
    let m = compat::scalar_hash(&msg);

    let s_i = m * k_i + sigma_i;

    // Spec 1.4
    let wait0 = chan.next_waitpoint();
    chan.send_many(wait0, &s_i).await;

    // Spec 2.1 + 2.2
    let mut seen = ParticipantCounter::new(&participants);
    let mut s = s_i;
    seen.put(me);
    while !seen.full() {
        let (from, s_j): (_, Scalar) = chan.recv(wait0).await?;
        if !seen.put(from) {
            continue;
        }
        s += s_j
    }

    // Spec 2.3
    let r = compat::x_coordinate(&presignature.big_k);
    let sig = Signature::from_scalars(r, s).map_err(|e| ProtocolError::Other(Box::new(e)))?;
    let sig = sig.normalize_s().unwrap_or(sig);

    if VerifyingKey::from(&public_key).verify(&msg, &sig).is_err() {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }

    // Spec 2.4
    Ok(FullSignature {
        big_k: presignature.big_k,
        sig,
    })
}

pub fn sign(
    participants: &[Participant],
    me: Participant,
    public_key: AffinePoint,
    presignature: PresignOutput,
    msg: &[u8],
) -> Result<impl Protocol<Output = FullSignature>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::BadParameters(format!(
            "participant count cannot be < 2, found: {}",
            participants.len()
        )));
    };

    let participants = ParticipantList::new(participants).ok_or_else(|| {
        InitializationError::BadParameters("participant list cannot contain duplicates".to_string())
    })?;

    let public_key = PublicKey::from_affine(public_key).map_err(|_| {
        InitializationError::BadParameters("public key cannot be identity point".to_string())
    })?;

    let ctx = Context::new();
    let fut = do_sign(
        ctx.shared_channel(),
        participants,
        me,
        public_key,
        presignature,
        msg.to_owned(),
    );
    Ok(run_protocol(ctx, fut))
}

#[cfg(test)]
mod test {
    use k256::ProjectivePoint;
    use rand_core::OsRng;

    use crate::{math::Polynomial, protocol::run_protocol};

    use super::*;

    #[test]
    fn test_sign() {
        let threshold = 2;
        let msg = b"hello?";

        // Run 4 times for flakiness reasons
        for _ in 0..4 {
            let f = Polynomial::random(&mut OsRng, threshold);
            let x = f.evaluate_zero();
            let public_key = (ProjectivePoint::GENERATOR * x).to_affine();

            let g = Polynomial::random(&mut OsRng, threshold);

            let k = g.evaluate_zero();
            let big_k = (ProjectivePoint::GENERATOR * k.invert().unwrap()).to_affine();

            let r = compat::x_coordinate(&big_k);
            let sigma = r * k * x;

            let h = Polynomial::extend_random(&mut OsRng, threshold, &sigma);

            let participants = vec![Participant::from(0u32), Participant::from(1u32)];
            let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = FullSignature>>)> =
                Vec::with_capacity(participants.len());
            for p in &participants {
                let p_scalar = p.scalar();
                let presignature = PresignOutput {
                    big_k,
                    k: g.evaluate(&p_scalar),
                    sigma: h.evaluate(&p_scalar),
                };
                let protocol = sign(&participants, *p, public_key, presignature, msg);
                assert!(protocol.is_ok());
                let protocol = protocol.unwrap();
                protocols.push((*p, Box::new(protocol)));
            }

            let result = run_protocol(protocols);
            assert!(result.is_ok());
        }
    }
}
