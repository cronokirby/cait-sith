use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand_core::CryptoRngCore;

use crate::protocol::{internal::{Communication, PrivateChannel}, Participant, ProtocolError};

pub async fn batch_random_ot_sender(
    mut rng: impl CryptoRngCore,
    mut chan: PrivateChannel,
) {
    // Spec 1
    let y = Scalar::generate_biased(&mut rng);
    let big_y = ProjectivePoint::GENERATOR * y;
    let big_z = big_y * y;

    let wait0 = chan.next_waitpoint();
    chan
        .send(wait0, &big_y.to_affine())
        .await;
}

pub async fn batch_random_ot_receiver(
    mut rng: impl CryptoRngCore,
    mut chan: PrivateChannel,
) -> Result<(), ProtocolError> {
    let wait0 = chan.next_waitpoint();
    let big_y: AffinePoint = chan.recv(wait0).await?;

    Ok(())
}
