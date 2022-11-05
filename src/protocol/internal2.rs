use event_listener::Event;
use serde::{de::DeserializeOwned, Serialize};
use smol::{
    channel,
    lock::{Mutex, RwLock},
    Executor,
};
use std::{collections::HashMap, future::Future, sync::Arc, task::Waker};

use super::{MessageData, Participant, ProtocolError};

// ChannelHeader lets us route to a specific channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Hash)]
enum BaseChannel {
    Shared,
    Private(Participant, Participant),
}

impl BaseChannel {
    /// Create a shared channel header.
    fn shared() -> Self {
        Self::Shared
    }

    /// Create a private channel header from participants.
    ///
    /// This will sort the participants, creating a unique channel
    /// for each unordered pair.
    fn private(p0: Participant, p1: Participant) -> Self {
        Self::Private(p0.min(p1), p0.max(p1))
    }
}

/// A sub channel, inside of a channel.
///
/// Used to allow multiple channels in parallel.
type SubChannel = u16;
/// A waitpoint inside of a channel.
pub type Waitpoint = u8;

/// A header used to route the message
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Hash)]
struct MessageHeader {
    /// Identifying the main channel.
    base_channel: BaseChannel,
    /// Identifying the sub channel.
    sub_channel: SubChannel,
    /// Identifying the specific waitpoint.
    waitpoint: Waitpoint,
}

impl MessageHeader {
    /// The number of bytes in this encoding.
    const LEN: usize = 12;

    fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];

        let (channel_type, part0, part1) = match self.base_channel {
            BaseChannel::Shared => (0, 0u32, 0u32),
            BaseChannel::Private(p0, p1) => (1, p0.into(), p1.into()),
        };

        out[0..4].copy_from_slice(&part0.to_le_bytes());
        out[4..8].copy_from_slice(&part1.to_le_bytes());
        out[8..10].copy_from_slice(&self.sub_channel.to_le_bytes());
        out[10] = channel_type;
        out[11] = self.waitpoint;

        out
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::LEN {
            return None;
        }
        // Unwrapping is fine because we checked the length already.
        let part0: Participant = u32::from_le_bytes(bytes[..4].try_into().unwrap()).into();
        let part1: Participant = u32::from_le_bytes(bytes[4..8].try_into().unwrap()).into();
        let sub_channel: u16 = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
        let channel_type: u8 = bytes[10];
        let waitpoint: Waitpoint = bytes[11];

        let base_channel = match channel_type {
            1 => BaseChannel::Private(part0, part1),
            _ => BaseChannel::Shared,
        };

        Some(Self {
            base_channel,
            sub_channel,
            waitpoint,
        })
    }

    fn with_waitpoint(&self, waitpoint: Waitpoint) -> Self {
        Self {
            base_channel: self.base_channel,
            sub_channel: self.sub_channel,
            waitpoint,
        }
    }

    fn next_waitpoint(&mut self) -> Waitpoint {
        let out = self.waitpoint;
        self.waitpoint += 1;
        out
    }

    /// Return the ith successor of this header.
    fn successor(&self, i: u16) -> Self {
        Self {
            base_channel: self.base_channel,
            sub_channel: self.sub_channel + i + 1,
            waitpoint: 0,
        }
    }

    fn channel_header(&self) -> (BaseChannel, SubChannel) {
        (self.base_channel, self.sub_channel)
    }
}

#[derive(Clone)]
struct MessageBuffer {
    messages: Arc<Mutex<HashMap<MessageHeader, Vec<(Participant, MessageData)>>>>,
    events: Arc<Mutex<HashMap<MessageHeader, Event>>>,
}

impl MessageBuffer {
    async fn push(&self, header: MessageHeader, from: Participant, message: MessageData) {
        let mut messages_lock = self.messages.as_ref().lock().await;
        messages_lock
            .entry(header)
            .or_default()
            .push((from, message));
        let mut events_lock = self.events.as_ref().lock().await;
        events_lock.entry(header).or_default().notify(1);
    }

    async fn pop(&self, header: MessageHeader) -> (Participant, MessageData) {
        loop {
            let listener = {
                let mut messages_lock = self.messages.as_ref().lock().await;
                let messages = messages_lock.entry(header).or_default();
                if let Some(out) = messages.pop() {
                    return out;
                }
                let mut events_lock = self.events.as_ref().lock().await;
                events_lock.entry(header).or_default().listen()
            };
            listener.await;
        }
    }
}

struct Comms {}

impl Comms {
    pub fn shared_channel(&self) -> SharedChannel {
        todo!()
    }

    pub fn private_channel(&self) -> PrivateChannel {
        todo!()
    }
}

struct SharedChannel {}

impl SharedChannel {
    pub fn successor(&self, i: u16) -> Self {
        todo!()
    }

    pub fn next_waitpoint(&mut self) -> Waitpoint {
        todo!()
    }

    pub async fn send_many<T: Serialize>(&self, waitpoint: Waitpoint, data: &T) {
        todo!()
    }

    pub async fn send_private<T: Serialize>(
        &self,
        waitpoint: Waitpoint,
        to: Participant,
        data: &T,
    ) {
        todo!()
    }

    pub async fn recv<T: DeserializeOwned>(
        &self,
        waitpoint: Waitpoint,
    ) -> Result<(Participant, T), ProtocolError> {
        todo!()
    }
}

struct PrivateChannel {}

impl PrivateChannel {
    pub fn successor(&self, i: u16) -> Self {
        todo!()
    }

    pub fn next_waitpoint(&mut self) -> Waitpoint {
        todo!()
    }

    pub async fn send<T: Serialize>(&self, waitpoint: Waitpoint, data: &T) {
        todo!()
    }

    pub async fn recv<T: DeserializeOwned>(
        &self,
        waitpoint: Waitpoint,
    ) -> Result<T, ProtocolError> {
        todo!()
    }
}

struct ProtocolExecutor<'a, T> {
    ret_r: channel::Receiver<T>,
    executor: Executor<'a>,
}

impl<'a, T: Send + 'a> ProtocolExecutor<'a, T> {
    fn new(fut: impl Future<Output = T> + Send + 'a) -> Self {
        let (ret_s, ret_r) = smol::channel::bounded(1);
        let fut = async move {
            let res = fut.await;
            ret_s
                .send(res)
                .await
                .expect("failed to return result of protocol");
        };

        let executor: Executor<'a> = Executor::new();
        executor.spawn(fut).detach();

        Self { ret_r, executor }
    }
}
