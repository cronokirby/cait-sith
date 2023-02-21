//! This module exists to provide internal utilities to construct protocols.
//!
//! The [`Protocol`] protocol interface is designed to be easy for outside consumers of the library to use.
//! Internally, we implement protocols by creating a state machine, which can switch between
//! the different states.
//!
//! Writing such a state machine by hand is extremely tedious. You'd need to create logic
//! to buffer messages for different rounds, and to wait for new messages to arrive.
//! This kind of mixing of state machine logic around networking and cryptography is also
//! very error prone, and makes the resulting code harder to understand.
//!
//! Thankfully, Rust already has a great tool for writing state machines: **async**!
//!
//! This module is about creating async utilities, and then providing a way to convert
//! a future created with async/await, which is just a state machine, into an instance
//! of the protocol interface.
//!
//! The basic idea is that you write your protocol using async await, with async functions
//! for sending and receiving messages.
//!
//! The tricky part is coordinating which round messages belong to.
//! The basic idea here is to use *waitpoints*. Each waitpoint represents a distinct point
//! in the protocol. This is sort of like rounds, except that waitpoints don't necessarily
//! have to follow eachother sequentially. For example, you can send on waitpoint A,
//! and then on waitpoint B, without first waiting to receive messages from waitpoint A.
//! This kind of decomposition can lead to better performance, and better matches what the
//! dependencies between messages in the protocol actually are.
//!
//! We also need a good way to handle concurrent composition of protocols.
//! This is mainly useful for some more advanced protocols, like triple generation, where we might
//! want to run multiple two-party protocols in parallel across an entire group of participants.
//! To do this, we also need some notion of channel in addition to waitpoints, and the ability
//! to have distinct channels to communicate on.
//!
//! We have two basic kinds of channels: channels which are intended to be shared to communicate
//! to all other participants, and channels which are supposed to be used for two-party
//! protocols. The two kinds won't conflict with each other. Given a channel, we can
//! also get new unique *children* channels, whose children will also be unique.
//!
//! One paramount thing about the identification system for channels is that both parties
//! agree on what the identifier for the channels in each part of the protocol is.
//! This is why we have to take great care that the identifiers a protocol will produce
//! are deterministic, even in the presence of concurrent tasks.
use ck_meow::Meow;
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

/// The domain for our use of meow here.
const MEOW_DOMAIN: &[u8] = b"cait-sith channel tags";

/// Represents a unique tag for a channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Hash)]
struct ChannelTag([u8; Self::SIZE]);

impl ChannelTag {
    /// 160 bit tags, enough for 80 bits of collision security, which should be ample.
    const SIZE: usize = 20;
    /// The channel tag for a shared channel.
    ///
    /// This will always yield the same tag, and is intended to be the root for shared channels.
    fn root_shared() -> Self {
        let mut out = [0u8; Self::SIZE];
        let mut meow = Meow::new(MEOW_DOMAIN);
        meow.meta_ad(b"root shared", false);
        meow.prf(&mut out, false);
        Self(out)
    }

    /// The channel tag for a private channel.
    ///
    /// This will always yield the same tag, and is intended to be the root for private channels.
    ///
    /// This tag will depend on the set of participants used; the order they're passed into this
    /// function does not matter.
    fn root_private(p0: Participant, p1: Participant) -> Self {
        // Sort participants, for uniqueness.
        let (p0, p1) = (p0.min(p1), p0.max(p1));
        let mut meow = Meow::new(MEOW_DOMAIN);
        meow.meta_ad(b"root private", false);
        meow.meta_ad(b"p0", false);
        meow.ad(&p0.bytes(), false);
        meow.meta_ad(b"p1", false);
        meow.ad(&p1.bytes(), false);
        let mut out = [0u8; Self::SIZE];
        meow.prf(&mut out, false);
        Self(out)
    }

    /// Get the ith child of this tag.
    ///
    /// Each child has its own "namespace", with its children being distinct.
    ///
    /// Indexed children have a separate namespace from named children.
    fn child(&self, i: u64) -> Self {
        let mut meow = Meow::new(MEOW_DOMAIN);
        meow.meta_ad(b"parent", false);
        meow.ad(&self.0, false);
        meow.meta_ad(b"i", false);
        meow.ad(&i.to_le_bytes(), false);
        let mut out = [0u8; Self::SIZE];
        meow.prf(&mut out, false);
        Self(out)
    }
}

/// A waitpoint inside of a channel.
pub type Waitpoint = u64;

/// A header used to route the message.
///
/// This header has a base channel, a sub channel, and then a final waitpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Hash)]
struct MessageHeader {
    /// Identifying the channel.
    channel: ChannelTag,
    /// Identifying the specific waitpoint.
    waitpoint: Waitpoint,
}

impl MessageHeader {
    /// The number of bytes in this encoding.
    const LEN: usize = ChannelTag::SIZE + 8;

    fn new(channel: ChannelTag) -> Self {
        Self {
            channel,
            waitpoint: 0,
        }
    }

    fn to_bytes(self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];

        out[..ChannelTag::SIZE].copy_from_slice(&self.channel.0);
        out[ChannelTag::SIZE..].copy_from_slice(&self.waitpoint.to_le_bytes());

        out
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::LEN {
            return None;
        }
        // Unwrapping is fine because we checked the length already.
        let channel = ChannelTag(bytes[..ChannelTag::SIZE].try_into().unwrap());
        let waitpoint = u64::from_le_bytes(bytes[ChannelTag::SIZE..Self::LEN].try_into().unwrap());

        Some(Self { channel, waitpoint })
    }

    /// Returns a new header with the waitpoint modified.
    fn with_waitpoint(&self, waitpoint: Waitpoint) -> Self {
        Self {
            channel: self.channel,
            waitpoint,
        }
    }

    /// Modify this header, incrementing the waitpoint.
    fn next_waitpoint(&mut self) -> Waitpoint {
        let out = self.waitpoint;
        self.waitpoint += 1;
        out
    }

    fn child(&self, i: u64) -> Self {
        Self {
            channel: self.channel.child(i),
            waitpoint: 0,
        }
    }
}

type SubMessageQueue = Vec<(Participant, MessageData)>;

/// A message buffer is a concurrent data structure to buffer messages.
///
/// The idea is that we can put messages, and have them organized according to the
/// header that addentifies where in the protocol those messages will be needed.
/// This data structure also provides async functions which allow efficiently
/// waiting until a particular message is available, by using events to sleep tasks
/// until a message for that slot has arrived.
#[derive(Clone)]
struct MessageBuffer {
    messages: Arc<Mutex<HashMap<MessageHeader, SubMessageQueue>>>,
    events: Arc<Mutex<HashMap<MessageHeader, Event>>>,
}

impl MessageBuffer {
    fn new() -> Self {
        Self {
            messages: Arc::new(Mutex::new(HashMap::new())),
            events: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Push a message into this buffer.
    ///
    /// We also need the header for the message, and the participant who sent it.
    async fn push(&self, header: MessageHeader, from: Participant, message: MessageData) {
        let mut messages_lock = self.messages.as_ref().lock().await;
        messages_lock
            .entry(header)
            .or_default()
            .push((from, message));
        let mut events_lock = self.events.as_ref().lock().await;
        events_lock.entry(header).or_default().notify(1);
    }

    /// Pop a message for a particular header.
    ///
    /// This will block until a message for that header is available. This will
    /// also correctly wake the underlying task when such a message arrives.
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

/// Represents a shared channel.
pub struct SharedChannel {
    header: MessageHeader,
    comms: Comms,
}

impl SharedChannel {
    fn new(comms: Comms) -> Self {
        Self {
            comms,
            header: MessageHeader::new(ChannelTag::root_shared()),
        }
    }

    /// Get the next available waitpoint on this channel.
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

/// Represents a private channel.
///
/// This can be seen as a separate "namespace" for `SharedChannel`.
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
            header: MessageHeader::new(ChannelTag::root_private(from, to)),
        }
    }

    pub fn child(&self, i: u64) -> Self {
        Self {
            comms: self.comms.clone(),
            to: self.to,
            header: self.header.child(i),
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

/// Represents the context that protocols have access to.
///
/// This allows us to spawn new tasks, and send and receive messages.
///
/// This context can safely be cloned.
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

    /// Return *the* shared channel for this context.
    ///
    /// To get other channels, use the successor function.
    pub fn shared_channel(&self) -> SharedChannel {
        SharedChannel::new(self.comms.clone())
    }

    /// Return *the* private channel for this context.
    ///
    /// To get other channels, use the successor function.
    pub fn private_channel(&self, from: Participant, to: Participant) -> PrivateChannel {
        PrivateChannel::new(self.comms.clone(), from, to)
    }

    /// Spawn a new task on the executor.
    pub fn spawn<T: Send + 'a>(&self, fut: impl Future<Output = T> + Send + 'a) -> Task<T> {
        self.executor.spawn(fut)
    }

    /// Run a future to completion on this executor.
    pub async fn run<T>(&self, fut: impl Future<Output = T>) -> T {
        self.executor.run(fut).await
    }
}

/// This struct will convert a future into a protocol.
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
        // This is a future which will keep ticking the executor until
        // all tasks are asleep, at which point it will indicate that nothing
        // is left to do, by returning `Action::Wait`.
        let fut_wait = async {
            while self.ctx.executor.try_tick() {
                // Now that we've ticked, we want to yield to allow the executor to poll
                // the other action sources.
                future::yield_now().await;
            }
            Ok(Action::Wait)
        };
        // The priority is first to send all outgoing messages before returning,
        // otherwise we might deadlock other people, by preventing them from receiving the output.
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

/// Run a protocol, converting a future into an instance of the Protocol trait.
pub fn make_protocol<'a, T: Send + 'a>(
    ctx: Context<'a>,
    fut: impl Future<Output = Result<T, ProtocolError>> + Send + 'a,
) -> impl Protocol<Output = T> + 'a {
    ProtocolExecutor::new(ctx, fut)
}
