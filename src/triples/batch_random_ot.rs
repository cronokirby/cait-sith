use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand_core::CryptoRngCore;

use crate::protocol::{internal::Communication, Participant, ProtocolError};

pub async fn batch_random_ot_sender(
    mut rng: impl CryptoRngCore,
    comms: Communication,
    me: Participant,
    them: Participant,
) {
    let chan0 = comms.next_channel();

    // Spec 1
    let y = Scalar::generate_biased(&mut rng);
    let big_y = ProjectivePoint::GENERATOR * y;
    let big_z = big_y * y;

    let wait0 = comms.next_waitpoint(chan0);
    comms
        .send_private(chan0, wait0, them, &big_y.to_affine())
        .await;
}

pub async fn batch_random_ot_receiver(
    mut rng: impl CryptoRngCore,
    comms: Communication,
    me: Participant,
    them: Participant,
) -> Result<(), ProtocolError> {
    let chan0 = comms.next_channel();

    let wait0 = comms.next_waitpoint(chan0);
    let big_y: AffinePoint = comms.recv_exclusive(chan0, wait0, them).await?;

    Ok(())
}
