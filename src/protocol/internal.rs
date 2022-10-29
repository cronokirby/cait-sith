use std::{
    cell::RefCell,
    collections::HashMap,
    error,
    future::Future,
    pin::Pin,
    ptr,
    rc::Rc,
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};

use ::serde::Serialize;
use serde::de::DeserializeOwned;

use crate::serde::{decode, encode_with_tag};

use super::{Action, MessageData, Participant, Protocol, ProtocolError};

// ChannelHeader lets us route to a specific channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Hash)]
enum ChannelHeader {
    SharedChannel,
    PrivateChannel(Participant, Participant),
}

impl ChannelHeader {
    /// Create a shared channel header.
    fn shared() -> Self {
        Self::SharedChannel
    }

    /// Create a private channel header from participants.
    ///
    /// This will sort the participants, creating a unique channel
    /// for each unordered pair.
    fn private(p0: Participant, p1: Participant) -> Self {
        Self::PrivateChannel(p0.min(p1), p0.max(p1))
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
    channel_header: ChannelHeader,
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

        let (channel_type, part0, part1) = match self.channel_header {
            ChannelHeader::SharedChannel => (0, 0u32, 0u32),
            ChannelHeader::PrivateChannel(p0, p1) => (1, p0.into(), p1.into()),
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

        let channel_header = match channel_type {
            1 => ChannelHeader::PrivateChannel(part0, part1),
            _ => ChannelHeader::SharedChannel,
        };

        Some(Self {
            channel_header,
            sub_channel,
            waitpoint,
        })
    }

    fn with_waitpoint(&self, waitpoint: Waitpoint) -> Self {
        Self {
            channel_header: self.channel_header,
            sub_channel: self.sub_channel,
            waitpoint,
        }
    }

    fn next_waitpoint(&mut self) -> Waitpoint {
        let out = self.waitpoint;
        self.waitpoint += 1;
        out
    }

    fn successor(&self) -> Self {
        Self {
            channel_header: self.channel_header,
            sub_channel: self.sub_channel + 1,
            waitpoint: 0,
        }
    }
}

/// Represents a queue of messages.
///
/// This is used to receive incoming messages as they arrive, and automatically
/// sort them into bins based on what channel and wait point they're for.
#[derive(Debug, Clone)]
struct MessageQueue {
    buffer: HashMap<MessageHeader, Vec<(Participant, MessageData)>>,
}

impl MessageQueue {
    /// Create a new message queue.
    fn new() -> Self {
        Self {
            buffer: HashMap::new(),
        }
    }

    /// Push a new message into the queue.
    ///
    /// This will read the first byte of the message to determine what round it
    /// belongs to.
    fn push(&mut self, from: Participant, message: MessageData) {
        if message.len() < MessageHeader::LEN {
            return;
        }

        let header = match MessageHeader::from_bytes(&message) {
            Some(h) => h,
            _ => return,
        };
        self.buffer.entry(header).or_default().push((from, message))
    }

    /// Pop a message from a specific header point.
    fn pop(&mut self, header: MessageHeader) -> Option<(Participant, MessageData)> {
        self.buffer.get_mut(&header)?.pop()
    }
}

/// A future which tries to read a message at a specific point.
struct MessageQueueWait {
    queue: Rc<RefCell<MessageQueue>>,
    header: MessageHeader,
}

impl MessageQueueWait {
    fn new(queue: Rc<RefCell<MessageQueue>>, header: MessageHeader) -> Self {
        Self { queue, header }
    }
}

impl Future for MessageQueueWait {
    type Output = (Participant, MessageData);

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.queue.borrow_mut().pop(self.header) {
            Some(out) => Poll::Ready(out),
            None => Poll::Pending,
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

/// A mailbox is a single item queue, used to handle message outputs.
///
/// The idea is that the future can write a message here, and then the executor
/// can pull it out.
#[derive(Debug)]
pub struct Mailbox(Option<Message>);

impl Mailbox {
    fn new() -> Self {
        Self(None)
    }

    /// Receive any message queued in here.
    fn recv(&mut self) -> Option<Message> {
        self.0.take()
    }
}

/// A future used to wait until a mailbox is emptied.
struct MailboxWait {
    mailbox: Rc<RefCell<Mailbox>>,
    /// This will always be some, but we need to be able to take it
    message: Option<Message>,
}

impl MailboxWait {
    fn new(mailbox: Rc<RefCell<Mailbox>>, message: Message) -> Self {
        Self {
            mailbox,
            message: Some(message),
        }
    }
}

impl Future for MailboxWait {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.mailbox.borrow().0.is_some() {
            return Poll::Pending;
        }
        let message = self.message.take();
        self.mailbox.borrow_mut().0 = message;
        Poll::Ready(())
    }
}

/// Represents the communications between the executor and the participant.
///
/// This allows the participant to read messages from the queue, possibly
/// waiting until a message for the round they're interested in arrives.
/// The participant can also push outgoing messages into a mailbox, allowing
/// the executor to pick them up.
#[derive(Debug)]
pub struct Communication {
    queue: Rc<RefCell<MessageQueue>>,
    mailbox: Rc<RefCell<Mailbox>>,
}

impl Communication {
    /// Create new communications.
    pub fn new() -> Self {
        let queue = MessageQueue::new();
        let mailbox = Mailbox::new();

        Self {
            queue: Rc::new(RefCell::new(queue)),
            mailbox: Rc::new(RefCell::new(mailbox)),
        }
    }

    fn push_message(&self, from: Participant, message: MessageData) {
        self.queue.borrow_mut().push(from, message);
    }

    fn outgoing(&self) -> Option<Message> {
        self.mailbox.borrow_mut().recv()
    }

    async fn send_raw(&self, data: Message) {
        MailboxWait::new(self.mailbox.clone(), data).await;
    }

    /// (Indicate that you want to) send a message to everybody else.
    async fn send_many<T: Serialize>(&self, header: MessageHeader, data: &T) {
        let header_bytes = header.to_bytes();
        let message_data = encode_with_tag(&header_bytes, data);
        self.send_raw(Message::Many(message_data)).await;
    }

    /// (Indicate that you want to) send a message privately to everybody else.
    async fn send_private<T: Serialize>(&self, header: MessageHeader, to: Participant, data: &T) {
        let header_bytes = header.to_bytes();
        let message_data = encode_with_tag(&header_bytes, data);
        self.send_raw(Message::Private(to, message_data)).await;
    }

    /// Receive a message for a specific round.
    async fn recv<T: DeserializeOwned>(
        &self,
        header: MessageHeader,
    ) -> Result<(Participant, T), ProtocolError> {
        let (from, data) = MessageQueueWait::new(self.queue.clone(), header).await;
        let decoded: Result<T, Box<dyn error::Error>> =
            decode(&data[MessageHeader::LEN..]).map_err(|e| e.into());
        Ok((from, decoded?))
    }

    /// Return the singular shared channel associated with these communications.
    ///
    /// Note that this will always return the same result, so you should use `successor`
    /// to get forked channels.
    pub fn shared_channel(&self) -> SharedChannel {
        SharedChannel::new(self.clone())
    }

    /// Return a private channel between two participants.
    ///
    /// The idea is that one person will use themselves as `from`, and the other person
    /// as `to`, and that person will do the opposite. They will end up with the same
    /// channel identifier, and can exchange messages across this channel immediately.
    pub fn private_channel(&self, from: Participant, to: Participant) -> PrivateChannel {
        PrivateChannel::new(self.clone(), from, to)
    }
}

impl Clone for Communication {
    fn clone(&self) -> Self {
        Self {
            queue: Rc::clone(&self.queue),
            mailbox: Rc::clone(&self.mailbox),
        }
    }
}

#[derive(Debug)]
pub struct SharedChannel {
    comms: Communication,
    header: MessageHeader,
}

impl SharedChannel {
    fn new(comms: Communication) -> Self {
        Self {
            comms,
            header: MessageHeader {
                channel_header: ChannelHeader::SharedChannel,
                sub_channel: 0,
                waitpoint: 0,
            },
        }
    }

    /// Returns the successor to this channel.
    ///
    /// This will also be a shared channel, but has an independent waitpoint set.
    pub fn successor(&self) -> Self {
        Self {
            comms: self.comms.clone(),
            header: self.header.successor(),
        }
    }

    /// Get the next available waitpoint on this shared channel.
    pub fn next_waitpoint(&mut self) -> Waitpoint {
        self.header.next_waitpoint()
    }

    /// Send some data to many participants on this channel.
    pub async fn send_many<T: Serialize>(&self, waitpoint: Waitpoint, data: &T) {
        self.comms
            .send_many(self.header.with_waitpoint(waitpoint), data)
            .await
    }

    /// Send a private message to another participant across this channel.
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

    /// Receive a message for a specific round.
    pub async fn recv<T: DeserializeOwned>(
        &self,
        waitpoint: Waitpoint,
    ) -> Result<(Participant, T), ProtocolError> {
        self.comms.recv(self.header.with_waitpoint(waitpoint)).await
    }
}

/// Represents a private channel shared between two participants.
#[derive(Debug)]
pub struct PrivateChannel {
    comms: Communication,
    to: Participant,
    header: MessageHeader,
}

impl PrivateChannel {
    fn new(comms: Communication, from: Participant, to: Participant) -> Self {
        Self {
            comms,
            to,
            header: MessageHeader {
                channel_header: ChannelHeader::PrivateChannel(from, to),
                sub_channel: 0,
                waitpoint: 0,
            },
        }
    }

    /// Return the successor to this channel.
    ///
    /// This is a private channel with an independent set of waitpoints.
    pub fn successor(&self) -> Self {
        Self {
            comms: self.comms.clone(),
            to: self.to,
            header: self.header.successor(),
        }
    }

    /// Return the next waitpoint for this channel.
    pub fn next_waitpoint(&mut self) -> Waitpoint {
        self.header.next_waitpoint()
    }

    /// Send a private message to the other participant on this channel.
    pub async fn send<T: Serialize>(&self, waitpoint: Waitpoint, data: &T) {
        self.comms
            .send_private(self.header.with_waitpoint(waitpoint), self.to, data)
            .await
    }

    /// Receive a message for a specific round.
    pub async fn recv<T: DeserializeOwned>(&self, waitpoint: Waitpoint) -> Result<T, ProtocolError> {
        loop {
            let (from, data) = self
                .comms
                .recv(self.header.with_waitpoint(waitpoint))
                .await?;
            if from != self.to {
                continue;
            }
            return Ok(data);
        }
    }
}

fn dummy_raw_waker() -> RawWaker {
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        dummy_raw_waker()
    }

    let vtable = &RawWakerVTable::new(clone, no_op, no_op, no_op);
    RawWaker::new(ptr::null(), vtable)
}

/// Just a waker which does nothing, which is fine for our dummy future, which doesn't use the waker.
fn dummy_waker() -> Waker {
    unsafe { Waker::from_raw(dummy_raw_waker()) }
}

/// An executor which implements our protocol trait.
///
/// You pass it a copy of the communications infrastructure, and then a future,
/// which will also use that same infrastructure. The executor then implements
/// the methods for advancing the protocol, which will end up polling the future
/// and reacting accordingly, based on what's happening on the communications infrastructure.
pub struct Executor<F, O> {
    comms: Communication,
    fut: Pin<Box<F>>,
    output: Option<O>,
    done: bool,
}

impl<O, F: Future<Output = Result<O, ProtocolError>>> Executor<F, O> {
    pub fn new(comms: Communication, fut: F) -> Self {
        Self {
            comms,
            fut: Box::pin(fut),
            output: None,
            done: false,
        }
    }

    fn take_output(&mut self) -> Option<O> {
        let out = self.output.take();
        if out.is_some() {
            self.done = true;
        }
        out
    }

    fn run(&mut self) -> Result<Action<O>, ProtocolError> {
        if self.done {
            return Ok(Action::Wait);
        }
        if let Some(out) = self.take_output() {
            return Ok(Action::Return(out));
        }

        let waker = dummy_waker();
        let mut ctx = Context::from_waker(&waker);
        if let Poll::Ready(out) = self.fut.as_mut().poll(&mut ctx) {
            self.output = Some(out?);
        }

        match self.comms.outgoing() {
            Some(Message::Many(m)) => Ok(Action::SendMany(m)),
            Some(Message::Private(to, m)) => Ok(Action::SendPrivate(to, m)),
            None => {
                if let Some(out) = self.take_output() {
                    Ok(Action::Return(out))
                } else {
                    Ok(Action::Wait)
                }
            }
        }
    }
}

impl<O, F: Future<Output = Result<O, ProtocolError>>> Protocol for Executor<F, O> {
    type Output = O;

    fn poke(&mut self) -> Result<Action<Self::Output>, ProtocolError> {
        self.run()
    }

    fn message(&mut self, from: Participant, data: MessageData) {
        self.comms.push_message(from, data);
    }
}
