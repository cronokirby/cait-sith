use std::vec::Vec;

use cait_sith::{
    keygen, presign,
    protocol::{run_protocol, Participant, Protocol},
    sign,
    triples::{
        self, generate_triple, setup, Setup, TripleGenerationOutput, TriplePub, TripleShare,
    },
    FullSignature, KeygenOutput, PresignArguments, PresignOutput,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use k256::{AffinePoint, Scalar, Secp256k1};
use rand_core::OsRng;

fn run_setup(participants: Vec<Participant>) -> Vec<(Participant, Setup)> {
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = Setup>>)> =
        Vec::with_capacity(participants.len());

    for p in participants.iter() {
        let protocol = setup::<Secp256k1>(&participants, *p);
        assert!(protocol.is_ok());
        let protocol = protocol.unwrap();
        protocols.push((*p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

fn run_triple_generation(
    participants: Vec<(Participant, Setup)>,
    threshold: usize,
) -> Vec<(Participant, TripleGenerationOutput<Secp256k1>)> {
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = TripleGenerationOutput<Secp256k1>>>,
    )> = Vec::with_capacity(participants.len());

    let just_participants: Vec<_> = participants.iter().map(|(p, _)| *p).collect();

    for (p, setup) in participants.into_iter() {
        let protocol = generate_triple(&just_participants, p, setup, threshold);
        assert!(protocol.is_ok());
        let protocol = protocol.unwrap();
        protocols.push((p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

fn run_keygen(
    participants: Vec<Participant>,
    threshold: usize,
) -> Vec<(Participant, KeygenOutput<Secp256k1>)> {
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
                original_threshold: threshold,
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

fn run_sign(
    participants: Vec<(Participant, PresignOutput<Secp256k1>)>,
    public_key: AffinePoint,
    msg: Scalar,
) -> Vec<(Participant, FullSignature<Secp256k1>)> {
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = FullSignature<Secp256k1>>>,
    )> = Vec::with_capacity(participants.len());

    let participant_list: Vec<Participant> = participants.iter().map(|(p, _)| *p).collect();

    for (p, presign_out) in participants.into_iter() {
        let protocol = sign(&participant_list, p, public_key, presign_out, msg);
        assert!(protocol.is_ok());
        let protocol = protocol.unwrap();
        protocols.push((p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let participants = vec![
        Participant::from(0u32),
        Participant::from(1u32),
        Participant::from(2u32),
    ];
    let t = 3;

    c.bench_function("setup 3", |b| b.iter(|| run_setup(participants.clone())));

    let mut setup_result = run_setup(participants.clone());
    setup_result.sort_by_key(|(p, _)| *p);

    c.bench_function("triple generation (3, 3)", |b| {
        b.iter(|| run_triple_generation(black_box(setup_result.clone()), t))
    });

    c.bench_function("keygen (3,3)", |b| {
        b.iter(|| run_keygen(black_box(participants.clone()), black_box(t)))
    });

    let mut keygen_result = run_keygen(participants.clone(), t);
    keygen_result.sort_by_key(|(p, _)| *p);

    let public_key = keygen_result[0].1.public_key;

    let (pub0, shares0) = triples::deal(&mut OsRng, &participants, t);
    let (pub1, shares1) = triples::deal(&mut OsRng, &participants, t);

    c.bench_function("presign (3,3)", |b| {
        b.iter(|| {
            run_presign(
                black_box(keygen_result.clone()),
                black_box(shares0.clone()),
                black_box(shares1.clone()),
                black_box(&pub0),
                black_box(&pub1),
                black_box(t),
            )
        })
    });

    let mut presign_result = run_presign(keygen_result, shares0, shares1, &pub0, &pub1, t);
    presign_result.sort_by_key(|(p, _)| *p);

    // DO NOT COPY THIS CODE FOR ACTUAL SIGNING
    let msg = Scalar::ONE;

    c.bench_function("sign (3,3)", |b| {
        b.iter(|| {
            run_sign(
                black_box(presign_result.clone()),
                black_box(public_key),
                black_box(msg),
            )
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
