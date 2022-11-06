use event_listener::Event;
use serde::{de::DeserializeOwned, Serialize};
use smol::{
    block_on,
    channel::{self, Receiver, Sender},
    future,
    lock::Mutex,
    Executor, Task,
};
use std::{collections::HashMap, error, future::Future, sync::Arc};

use crate::serde::{decode, encode_with_tag};

use super::{Action, MessageData, Participant, Protocol, ProtocolError};

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
    fn new() -> Self {
        Self {
            messages: Arc::new(Mutex::new(HashMap::new())),
            events: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn push(&self, header: MessageHeader, from: Participant, message: MessageData) {
        dbg!("pushing...");
        let mut messages_lock = self.messages.as_ref().lock().await;
        dbg!("got messages lock...");
        messages_lock
            .entry(header)
            .or_default()
            .push((from, message));
        let mut events_lock = self.events.as_ref().lock().await;
        dbg!("got events lock...");
        events_lock.entry(header).or_default().notify(1);
    }

    async fn pop(&self, header: MessageHeader) -> (Participant, MessageData) {
        loop {
            dbg!("acquiring listener");
            let listener = {
                let mut messages_lock = self.messages.as_ref().lock().await;
                let messages = messages_lock.entry(header).or_default();
                if let Some(out) = messages.pop() {
                    return out;
                }
                let mut events_lock = self.events.as_ref().lock().await;
                events_lock.entry(header).or_default().listen()
            };
            dbg!("listening...");
            listener.await;
        }
    }
}

/// Used to represent the different kinds of messages a participant can send.
///
/// This is basically used to communicate between the future and the executor.
#[derive(Debug, Clone)]
pub enum Message {
    Many(MessageData),
    Private(Participant, MessageData),
}

#[derive(Clone)]
struct Comms {
    buffer: MessageBuffer,
    message_s: Sender<Message>,
    message_r: Receiver<Message>,
}

impl Comms {
    pub fn new() -> Self {
        let (message_s, message_r) = channel::bounded(1);

        Self {
            buffer: MessageBuffer::new(),
            message_s,
            message_r,
        }
    }

    async fn outgoing(&self) -> Message {
        self.message_r
            .recv()
            .await
            .expect("failed to check outgoing messages")
    }

    async fn push_message(&self, from: Participant, message: MessageData) {
        if message.len() < MessageHeader::LEN {
            return;
        }

        let header = match MessageHeader::from_bytes(&message) {
            Some(h) => h,
            _ => return,
        };

        self.buffer.push(header, from, message).await
    }

    async fn send_raw(&self, data: Message) {
        self.message_s
            .send(data)
            .await
            .expect("failed to send message");
    }

    /// (Indicate that you want to) send a message to everybody else.
    async fn send_many<T: Serialize>(&self, header: MessageHeader, data: &T) {
        let header_bytes = header.to_bytes();
        let message_data = encode_with_tag(&header_bytes, data);
        self.send_raw(Message::Many(message_data)).await;
    }

    /// (Indicate that you want to) send a message privately to someone.
    async fn send_private<T: Serialize>(&self, header: MessageHeader, to: Participant, data: &T) {
        let header_bytes = header.to_bytes();
        let message_data = encode_with_tag(&header_bytes, data);
        self.send_raw(Message::Private(to, message_data)).await;
    }

    async fn recv<T: DeserializeOwned>(
        &self,
        header: MessageHeader,
    ) -> Result<(Participant, T), ProtocolError> {
        let (from, data) = self.buffer.pop(header).await;
        let decoded: Result<T, Box<dyn error::Error + Send + Sync>> =
            decode(&data[MessageHeader::LEN..]).map_err(|e| e.into());
        Ok((from, decoded?))
    }
}

pub struct SharedChannel {
    header: MessageHeader,
    comms: Comms,
}

impl SharedChannel {
    fn new(comms: Comms) -> Self {
        Self {
            comms,
            header: MessageHeader {
                base_channel: BaseChannel::Shared,
                sub_channel: 0,
                waitpoint: 0,
            },
        }
    }

    pub fn successor(&self, i: u16) -> Self {
        Self {
            comms: self.comms.clone(),
            header: self.header.successor(i),
        }
    }

    pub fn next_waitpoint(&mut self) -> Waitpoint {
        self.header.next_waitpoint()
    }

    pub async fn send_many<T: Serialize>(&self, waitpoint: Waitpoint, data: &T) {
        self.comms
            .send_many(self.header.with_waitpoint(waitpoint), data)
            .await
    }

    pub async fn send_private<T: Serialize>(
        &self,
        waitpoint: Waitpoint,
        to: Participant,
        data: &T,
    ) {
        self.comms
            .send_private(self.header.with_waitpoint(waitpoint), to, data)
            .await
    }

    pub async fn recv<T: DeserializeOwned>(
        &self,
        waitpoint: Waitpoint,
    ) -> Result<(Participant, T), ProtocolError> {
        self.comms.recv(self.header.with_waitpoint(waitpoint)).await
    }
}

pub struct PrivateChannel {
    header: MessageHeader,
    to: Participant,
    comms: Comms,
}

impl PrivateChannel {
    fn new(comms: Comms, from: Participant, to: Participant) -> Self {
        Self {
            comms,
            to,
            header: MessageHeader {
                base_channel: BaseChannel::private(from, to),
                sub_channel: 0,
                waitpoint: 0,
            },
        }
    }

    pub fn successor(&self, i: u16) -> Self {
        Self {
            comms: self.comms.clone(),
            to: self.to,
            header: self.header.successor(i),
        }
    }

    pub fn next_waitpoint(&mut self) -> Waitpoint {
        self.header.next_waitpoint()
    }

    pub async fn send<T: Serialize>(&self, waitpoint: Waitpoint, data: &T) {
        self.comms
            .send_private(self.header.with_waitpoint(waitpoint), self.to, data)
            .await
    }

    pub async fn recv<T: DeserializeOwned>(
        &self,
        waitpoint: Waitpoint,
    ) -> Result<T, ProtocolError> {
        loop {
            let (from, data) = self
                .comms
                .recv(self.header.with_waitpoint(waitpoint))
                .await?;
            if from != self.to {
                future::yield_now().await;
                continue;
            }
            return Ok(data);
        }
    }
}

#[derive(Clone)]
pub struct Context<'a> {
    comms: Comms,
    executor: Arc<Executor<'a>>,
}

impl<'a> Context<'a> {
    pub fn new() -> Self {
        Self {
            comms: Comms::new(),
            executor: Arc::new(Executor::new()),
        }
    }

    pub fn shared_channel(&self) -> SharedChannel {
        SharedChannel::new(self.comms.clone())
    }

    pub fn private_channel(&self, from: Participant, to: Participant) -> PrivateChannel {
        PrivateChannel::new(self.comms.clone(), from, to)
    }

    pub fn spawn<T: Send + 'a>(&self, fut: impl Future<Output = T> + Send + 'a) -> Task<T> {
        self.executor.spawn(fut)
    }

    pub async fn run<T>(&self, fut: impl Future<Output = T>) -> T {
        self.executor.run(fut).await
    }
}

struct ProtocolExecutor<'a, T> {
    ctx: Context<'a>,
    ret_r: channel::Receiver<Result<T, ProtocolError>>,
    done: bool,
}

impl<'a, T: Send + 'a> ProtocolExecutor<'a, T> {
    fn new(
        ctx: Context<'a>,
        fut: impl Future<Output = Result<T, ProtocolError>> + Send + 'a,
    ) -> Self {
        let (ret_s, ret_r) = smol::channel::bounded(1);
        let fut = async move {
            let res = fut.await;
            ret_s
                .send(res)
                .await
                .expect("failed to return result of protocol");
        };

        ctx.executor.spawn(fut).detach();

        Self {
            ctx,
            ret_r,
            done: false,
        }
    }
}

impl<'a, T> Protocol for ProtocolExecutor<'a, T> {
    type Output = T;

    fn poke(&mut self) -> Result<Action<Self::Output>, ProtocolError> {
        if self.done {
            return Ok(Action::Wait);
        }
        let fut_return = async {
            let out = self
                .ret_r
                .recv()
                .await
                .expect("failed to retrieve return value");
            Ok::<_, ProtocolError>(Action::Return(out?))
        };
        let fut_outgoing = async {
            let action: Action<Self::Output> = match self.ctx.comms.outgoing().await {
                Message::Many(m) => Action::SendMany(m),
                Message::Private(to, m) => Action::SendPrivate(to, m),
            };
            Ok::<_, ProtocolError>(action)
        };
        let fut_wait = async {
            while { self.ctx.executor.try_tick() } {
                future::yield_now().await;
            }
            Ok(Action::Wait)
        };
        let action = block_on(
            self.ctx
                .run(future::or(fut_outgoing, future::or(fut_return, fut_wait))),
        );
        match action {
            Err(_) => self.done = true,
            Ok(Action::Return(_)) => self.done = true,
            _ => {}
        };
        action
    }

    fn message(&mut self, from: Participant, data: MessageData) {
        block_on(
            self.ctx
                .executor
                .run(self.ctx.comms.push_message(from, data)),
        );
    }
}

pub fn run_protocol<'a, T: Send + 'a>(
    ctx: Context<'a>,
    fut: impl Future<Output = Result<T, ProtocolError>> + Send + 'a,
) -> impl Protocol<Output = T> + 'a {
    ProtocolExecutor::new(ctx, fut)
}
