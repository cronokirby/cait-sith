use k256::{AffinePoint, Secp256k1};
use rand_core::OsRng;

use crate::{
    compat::scalar_hash,
    keygen, presign,
    protocol::{run_protocol, Participant, Protocol},
    sign,
    triples::{self, TriplePub, TripleShare},
    FullSignature, KeygenOutput, PresignArguments, PresignOutput,
};

fn run_keygen(
    participants: Vec<Participant>,
    threshold: usize,
) -> Vec<(Participant, KeygenOutput<Secp256k1>)> {
    #[allow(clippy::type_complexity)]
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = KeygenOutput<Secp256k1>>>,
    )> = Vec::with_capacity(participants.len());

    for p in participants.iter() {
        let protocol = keygen(&participants, *p, threshold);
        assert!(protocol.is_ok());
        let protocol = protocol.unwrap();
        protocols.push((*p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

fn run_presign(
    participants: Vec<(Participant, KeygenOutput<Secp256k1>)>,
    shares0: Vec<TripleShare<Secp256k1>>,
    shares1: Vec<TripleShare<Secp256k1>>,
    pub0: &TriplePub<Secp256k1>,
    pub1: &TriplePub<Secp256k1>,
    threshold: usize,
) -> Vec<(Participant, PresignOutput<Secp256k1>)> {
    assert!(participants.len() == shares0.len());
    assert!(participants.len() == shares1.len());

    #[allow(clippy::type_complexity)]
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = PresignOutput<Secp256k1>>>,
    )> = Vec::with_capacity(participants.len());

    let participant_list: Vec<Participant> = participants.iter().map(|(p, _)| *p).collect();

    for (((p, keygen_out), share0), share1) in participants
        .into_iter()
        .zip(shares0.into_iter())
        .zip(shares1.into_iter())
    {
        let protocol = presign(
            &participant_list,
            p,
            PresignArguments {
                triple0: (share0, pub0.clone()),
                triple1: (share1, pub1.clone()),
                keygen_out,
                threshold,
            },
        );
        assert!(protocol.is_ok());
        let protocol = protocol.unwrap();
        protocols.push((p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

#[allow(clippy::type_complexity)]
fn run_sign(
    participants: Vec<(Participant, PresignOutput<Secp256k1>)>,
    public_key: AffinePoint,
    msg: &[u8],
) -> Vec<(Participant, FullSignature<Secp256k1>)> {
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = FullSignature<Secp256k1>>>,
    )> = Vec::with_capacity(participants.len());

    let participant_list: Vec<Participant> = participants.iter().map(|(p, _)| *p).collect();

    for (p, presign_out) in participants.into_iter() {
        let protocol = sign(
            &participant_list,
            p,
            public_key,
            presign_out,
            scalar_hash(msg),
        );
        assert!(protocol.is_ok());
        let protocol = protocol.unwrap();
        protocols.push((p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

#[test]
fn test_e2e() {
    let participants = vec![
        Participant::from(0u32),
        Participant::from(1u32),
        Participant::from(2u32),
    ];
    let t = 3;

    let mut keygen_result = run_keygen(participants.clone(), t);
    keygen_result.sort_by_key(|(p, _)| *p);

    let public_key = keygen_result[0].1.public_key;
    assert_eq!(keygen_result[0].1.public_key, keygen_result[1].1.public_key);
    assert_eq!(keygen_result[1].1.public_key, keygen_result[2].1.public_key);

    let (pub0, shares0) = triples::deal(&mut OsRng, &participants, t);
    let (pub1, shares1) = triples::deal(&mut OsRng, &participants, t);

    let mut presign_result = run_presign(keygen_result, shares0, shares1, &pub0, &pub1, t);
    presign_result.sort_by_key(|(p, _)| *p);

    let msg = b"hello world";

    run_sign(presign_result, public_key, msg);
}
