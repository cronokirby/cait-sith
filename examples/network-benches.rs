use std::{collections::HashMap, time::{Duration, Instant}};

use cait_sith::{
    keygen,
    protocol::{Action, Participant, Protocol},
};
use easy_parallel::Parallel;
use haisou_chan::{channel, ChannelSettings};

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Args {
    /// The number of parties to run the benchmarks with.
    parties: u32,
    /// The latency, in milliseconds.
    latency_ms: u32,
    /// The bandwidth, in bytes per second.
    bandwidth: u32,
    #[structopt(long = "runs", default_value = "10")]
    runs: u32,
}

#[derive(Debug, Clone, Copy)]
struct Stats {
    sent: usize,
    received: usize,
}

fn run_protocol<T, F, P>(
    settings: ChannelSettings,
    participants: &[Participant],
    f: F,
) -> Vec<(Participant, Stats, T)>
where
    F: Fn(Participant) -> P + Send + Sync,
    P: Protocol<Output = T>,
    T: Send + std::fmt::Debug,
{
    let mut senders: HashMap<_, _> = participants.iter().map(|p| (p, HashMap::new())).collect();
    let mut receivers: HashMap<_, _> = participants.iter().map(|p| (p, Vec::new())).collect();

    for p in participants {
        for q in participants {
            if p >= q {
                continue;
            }
            let (sender0, receiver0) = channel(settings);
            let (sender1, receiver1) = channel(settings);
            senders.get_mut(p).unwrap().insert(q, sender0);
            senders.get_mut(q).unwrap().insert(p, sender1);
            receivers.get_mut(p).unwrap().push((q, receiver1));
            receivers.get_mut(q).unwrap().push((p, receiver0));
        }
    }

    let executor = smol::Executor::new();

    let mut next_messages = HashMap::new();
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
        next_messages.insert(p, receiver);
    }

    let setup = participants.iter().map(|p| {
        let next_message = next_messages.remove(p).unwrap();
        let senders = senders.remove(p).unwrap();
        (p, next_message, senders)
    });

    let mut out = Parallel::new()
        .each(setup, |(p, next_message, mut senders)| {
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
                                for sender in senders.values_mut() {
                                    stats.sent += m.len();
                                    sender.send(m.clone()).await.unwrap();
                                }
                            }
                            Action::SendPrivate(q, m) => {
                                stats.sent += m.len();
                                senders.get_mut(&q).unwrap().send(m).await.unwrap();
                            }
                            Action::Return(r) => return (*p, stats, r),
                        }
                    }
                    let (from, m) = next_message.recv().await.unwrap();
                    stats.received += m.len();
                    prot.message(from, m);
                }
            }))
        })
        .run();

    out.sort_by_key(|(p, _, _)| *p);

    out
}

fn report_stats<I>(iter: I) where I: Iterator<Item = Stats> {
    let mut count = 0;
    let mut avg_up = 0;
    let mut avg_down = 0;
    iter.for_each(|stats| {
        count += 1;
        avg_up += stats.sent;
        avg_down += stats.received;
    });
    println!("up:\t {} B", avg_up);
    println!("down:\t {} B", avg_down);
}

fn main() {
    let args = Args::from_args();
    let settings = ChannelSettings {
        latency: Duration::from_millis(args.latency_ms as u64),
        bandwidth: args.bandwidth,
    };
    let participants: Vec<_> = (0..args.parties)
        .map(|p| Participant::from(p as u32))
        .collect();
    println!("Keygen ({}, {}) [{} ms, {} B/S]", args.parties, args.parties, args.latency_ms, args.bandwidth);
    let start = Instant::now();
    let results = run_protocol(settings, &participants, |p| {
        keygen(&participants, p, args.parties as usize).unwrap()
    });
    let stop = Instant::now();
    println!("time:\t{:#?}", stop.duration_since(start));
    report_stats(results.iter().map(|(_, stats, _)| *stats));
}
