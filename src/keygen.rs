use k256::{AffinePoint, Scalar};
use magikitten::Transcript;
use rand_core::CryptoRngCore;

use crate::math::Polynomial;
use crate::participants::ParticipantList;
use crate::protocol::internal::{Communication, Executor};
use crate::protocol::{InitializationError, Participant, Protocol, ProtocolError};
use crate::serde::encode;

pub struct KeygenOutput {
    private_share: Scalar,
    public_key: AffinePoint,
}

async fn do_keygen(
    rng: &mut impl CryptoRngCore,
    comms: Communication,
    participants: ParticipantList,
    threshold: usize,
) -> Result<KeygenOutput, ProtocolError> {
    let mut transcript = Transcript::new(b"cait-sith v0.1.0 keygen");

    // Spec 1.2
    transcript.message(b"participants", &encode(&participants));
    // To allow interop between platforms where usize is different!
    transcript.message(
        b"threshold",
        &u64::try_from(threshold).unwrap().to_be_bytes(),
    );

    // Spec 1.3
    let f = Polynomial::random(rng, threshold);

    // Spec 1.4
    todo!()
}

pub fn keygen<'a>(
    rng: &'a mut impl CryptoRngCore,
    participants: &[Participant],
    threshold: usize,
) -> Result<impl Protocol<Output = KeygenOutput> + 'a, InitializationError> {
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

    let comms = Communication::new(4, participants.len());
    let fut = do_keygen(rng, comms.clone(), participants, threshold);
    Ok(Executor::new(comms, fut))
}
