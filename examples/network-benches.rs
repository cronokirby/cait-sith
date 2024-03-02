use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use cait_sith::{
    keygen, presign,
    protocol::{Action, MessageData, Participant, Protocol},
    sign, triples, PresignArguments,
};
use digest::{Digest, FixedOutput};
use easy_parallel::Parallel;
use ecdsa::hazmat::DigestPrimitive;
use elliptic_curve::{ops::Reduce, Curve};
use haisou_chan::{channel, Bandwidth};

use k256::{FieldBytes, Scalar, Secp256k1};
use rand_core::OsRng;
use structopt::StructOpt;

fn scalar_hash(msg: &[u8]) -> Scalar {
    let digest = <Secp256k1 as DigestPrimitive>::Digest::new_with_prefix(msg);
    let m_bytes: FieldBytes = digest.finalize_fixed();
    <Scalar as Reduce<<Secp256k1 as Curve>::Uint>>::reduce_bytes(&m_bytes)
}

#[derive(Debug)]
enum BatchSize {
    S = 10,  
    M = 100,
    L = 1000,
}

impl BatchSize {
    fn from_value(value: u32) -> Self {
        match value {
            10 => BatchSize::S,
            100 => BatchSize::M,
            1000 => BatchSize::L,
            _ => BatchSize::S,
        }
    }
}

#[derive(Debug, StructOpt)]
struct Args {
    /// The number of parties to run the benchmarks with.
    parties: u32,
    /// The latency, in milliseconds.
    latency_ms: u32,
    /// The bandwidth, in bytes per second.
    bandwidth: u32,
    /// The batch size.
    batch_size: u32,
}

#[derive(Debug, Clone, Copy)]
struct Stats {
    sent: usize,
    received: usize,
}

fn run_protocol<T, F, P>(
    latency: Duration,
    bandwidth: Bandwidth,
    participants: &[Participant],
    f: F,
) -> Vec<(Participant, Stats, T)>
where
    F: Fn(Participant) -> P + Send + Sync,
    P: Protocol<Output = T>,
    T: Send,
{
    // We create a link between each pair of parties, with a set amount of latency,
    // but no bandwidth constraints.
    let mut senders: HashMap<_, _> = participants.iter().map(|p| (p, HashMap::new())).collect();
    let mut receivers: HashMap<_, _> = participants.iter().map(|p| (p, Vec::new())).collect();

    for p in participants {
        for q in participants {
            if p >= q {
                continue;
            }
            let (sender0, mut receiver0) = channel();
            let (sender1, mut receiver1) = channel();
            receiver0.set_latency(latency);
            receiver1.set_latency(latency);
            senders.get_mut(p).unwrap().insert(q, sender0);
            senders.get_mut(q).unwrap().insert(p, sender1);
            receivers.get_mut(p).unwrap().push((q, receiver1));
            receivers.get_mut(q).unwrap().push((p, receiver0));
        }
    }

    let executor = smol::Executor::new();

    // Next, we create a bottleneck link which every outgoing message passes through,
    // which limits how fast data can be transmitted away from the node.
    let mut outgoing = HashMap::new();
    for (p, mut senders) in senders {
        let (mut bottleneck_s, bottleneck_r) = channel();
        bottleneck_s.set_bandwidth(bandwidth);
        executor
            .spawn(async move {
                loop {
                    let (to, msg): (Participant, MessageData) = match bottleneck_r.recv().await {
                        Ok(x) => x,
                        Err(_) => return,
                    };
                    senders
                        .get_mut(&to)
                        .unwrap()
                        .send(msg.len(), msg)
                        .await
                        .unwrap();
                }
            })
            .detach();
        outgoing.insert(p, bottleneck_s);
    }

    // For convenience, we create a channel in order to receive the first
    // available message across any of the parties.
    let mut incoming = HashMap::new();
    for (p, receivers) in receivers {
        let (sender, receiver) = smol::channel::unbounded();
        for (q, r) in receivers {
            executor
                .spawn({
                    let sender = sender.clone();
                    async move {
                        loop {
                            let msg = match r.recv().await {
                                Ok(msg) => msg,
                                Err(_) => return,
                            };
                            sender.send((*q, msg)).await.unwrap();
                        }
                    }
                })
                .detach();
        }
        incoming.insert(p, receiver);
    }

    let setup = participants.iter().map(|p| {
        let incoming = incoming.remove(p).unwrap();
        let outgoing = outgoing.remove(p).unwrap();
        (p, outgoing, incoming)
    });

    // Now we run all of the protocols in parallel, on a different thread.
    let mut out = Parallel::new()
        .each(setup, |(p, mut outgoing, incoming)| {
            smol::block_on(executor.run(async {
                let mut prot = f(*p);
                let mut stats = Stats {
                    sent: 0,
                    received: 0,
                };
                loop {
                    loop {
                        let poked = prot.poke().unwrap();
                        match poked {
                            Action::Wait => break,
                            Action::SendMany(m) => {
                                for q in participants {
                                    if p == q {
                                        continue;
                                    }
                                    stats.sent += m.len();
                                    outgoing.send(m.len(), (*q, m.clone())).await.unwrap();
                                }
                            }
                            Action::SendPrivate(q, m) => {
                                stats.sent += m.len();
                                outgoing.send(m.len(), (q, m.clone())).await.unwrap();
                            }
                            Action::Return(r) => return (*p, stats, r),
                        }
                    }
                    let (from, m) = incoming.recv().await.unwrap();
                    stats.received += m.len();
                    prot.message(from, m);
                }
            }))
        })
        .run();

    out.sort_by_key(|(p, _, _)| *p);

    out
}

fn report_stats<I>(iter: I)
where
    I: Iterator<Item = Stats>,
{
    let mut count = 0;
    let mut avg_up = 0;
    let mut avg_down = 0;
    iter.for_each(|stats| {
        count += 1;
        avg_up += stats.sent;
        avg_down += stats.received;
    });
    avg_up /= count;
    avg_down /= count;
    println!("up:\t {} B", avg_up);
    println!("down:\t {} B", avg_down);
}

fn main() {
    let args = Args::from_args();
    let latency = Duration::from_millis(args.latency_ms as u64);
    let bandwidth = args.bandwidth;
    let batch_size = BatchSize::from_value(args.batch_size);
    let participants: Vec<_> = (0..args.parties)
        .map(|p| Participant::from(p as u32))
        .collect();

    
    println!(
        "\nBatch (N={:?}) Triple Gen {} [{} ms, {} B/S]",
        batch_size, args.parties, args.latency_ms, args.bandwidth
    );
    let start = Instant::now();
    let results = match batch_size {
        BatchSize::S => run_protocol(latency, bandwidth, &participants, |p| {
            triples::generate_triple_many::<Secp256k1, 10>(&participants, p, args.parties as usize)
                .unwrap()
        }),
        BatchSize::M => run_protocol(latency, bandwidth, &participants, |p| {
            triples::generate_triple_many::<Secp256k1, 100>(&participants, p, args.parties as usize)
                .unwrap()
        }),
        BatchSize::L => run_protocol(latency, bandwidth, &participants, |p| {
            triples::generate_triple_many::<Secp256k1, 1000>(&participants, p, args.parties as usize)
                .unwrap()
        }),
    };
    let stop = Instant::now();
    println!("time:\t{:#?}", stop.duration_since(start));
    report_stats(results.iter().map(|(_, stats, _)| *stats));

    println!(
        "\nTriple Gen {} [{} ms, {} B/S]",
        args.parties, args.latency_ms, args.bandwidth
    );
    let start = Instant::now();
    let results = run_protocol(latency, bandwidth, &participants, |p| {
        triples::generate_triple::<Secp256k1>(&participants, p, args.parties as usize).unwrap()
    });
    let stop = Instant::now();
    println!("time:\t{:#?}", stop.duration_since(start));
    report_stats(results.iter().map(|(_, stats, _)| *stats));

    let triples: HashMap<_, _> = results.into_iter().map(|(p, _, out)| (p, out)).collect();

    println!(
        "\nKeygen ({}, {}) [{} ms, {} B/S]",
        args.parties, args.parties, args.latency_ms, args.bandwidth
    );
    let start = Instant::now();
    let results = run_protocol(latency, bandwidth, &participants, |p| {
        keygen(&participants, p, args.parties as usize).unwrap()
    });
    let stop = Instant::now();
    println!("time:\t{:#?}", stop.duration_since(start));
    report_stats(results.iter().map(|(_, stats, _)| *stats));

    let shares: HashMap<_, _> = results.into_iter().map(|(p, _, out)| (p, out)).collect();

    let (other_triples_pub, other_triples_share) =
        triples::deal(&mut OsRng, &participants, args.parties as usize);
    let other_triples: HashMap<_, _> = participants
        .iter()
        .zip(other_triples_share)
        .map(|(p, share)| (p, (share, other_triples_pub.clone())))
        .collect();

    println!(
        "\nPresign ({}, {}) [{} ms, {} B/S]",
        args.parties, args.parties, args.latency_ms, args.bandwidth
    );
    let start = Instant::now();
    let results = run_protocol(latency, bandwidth, &participants, |p| {
        presign(
            &participants,
            p,
            PresignArguments {
                triple0: triples[&p].clone(),
                triple1: other_triples[&p].clone(),
                keygen_out: shares[&p].clone(),
                threshold: args.parties as usize,
            },
        )
        .unwrap()
    });
    let stop = Instant::now();
    println!("time:\t{:#?}", stop.duration_since(start));
    report_stats(results.iter().map(|(_, stats, _)| *stats));

    let presignatures: HashMap<_, _> = results.into_iter().map(|(p, _, out)| (p, out)).collect();

    println!(
        "\nSign ({}, {}) [{} ms, {} B/S]",
        args.parties, args.parties, args.latency_ms, args.bandwidth
    );
    let start = Instant::now();
    let results = run_protocol(latency, bandwidth, &participants, |p| {
        sign(
            &participants,
            p,
            shares[&p].public_key,
            presignatures[&p].clone(),
            scalar_hash(b"hello world"),
        )
        .unwrap()
    });
    let stop = Instant::now();
    println!("time:\t{:#?}", stop.duration_since(start));
    report_stats(results.iter().map(|(_, stats, _)| *stats));
}
