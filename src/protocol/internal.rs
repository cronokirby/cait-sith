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

/// A waiting point in the queue.
pub type Waitpoint = u8;
/// Represents a specific channel we can send messages on.
///
/// The idea is that we can have multiple channels, allowing us to run protocols in parallel.
pub type Channel = u8;

/// Represents a queue of messages.
///
/// This is used to receive incoming messages as they arrive, and automatically
/// sort them into bins based on
#[derive(Debug, Clone)]
struct MessageQueue {
    next_channel: Channel,
    next_waitpoints: Vec<Waitpoint>,
    buffer: HashMap<(Channel, Waitpoint), Vec<(Participant, MessageData)>>,
}

impl MessageQueue {
    /// Create a new message queue.
    fn new() -> Self {
        Self {
            next_channel: 0,
            next_waitpoints: vec![0; 256],
            buffer: HashMap::new(),
        }
    }

    /// Get the next waitpoint.
    fn next_waitpoint(&mut self, chan: Channel) -> Waitpoint {
        let wp = &mut self.next_waitpoints[usize::from(chan)];
        let out = *wp;
        assert!(out < 0xFF, "max number of waitpoints reached");
        *wp += 1;
        out
    }

    /// Get the next available channel.
    fn next_channel(&mut self) -> Channel {
        let out = self.next_channel;
        assert!(out < 0xFF, "max number of channels reached");
        self.next_channel += 1;
        out
    }

    /// Push a new message into the queue.
    ///
    /// This will read the first byte of the message to determine what round it
    /// belongs to.
    fn push(&mut self, from: Participant, message: MessageData) {
        if message.is_empty() {
            return;
        }

        let channel = message[0];
        let waitpoint = message[1];

        self.buffer.entry((channel, waitpoint)).or_default().push((from, message));
    }

    /// Pop a message from a specific channel and waitpoint
    fn pop(
        &mut self,
        channel: Channel,
        waitpoint: Waitpoint,
    ) -> Option<(Participant, MessageData)> {
        self.buffer.get_mut(&(channel, waitpoint))?.pop()
    }
}

/// A future which tries to read a message from a specific round.
struct MessageQueueWait {
    queue: Rc<RefCell<MessageQueue>>,
    channel: Channel,
    waitpoint: Waitpoint,
}

impl MessageQueueWait {
    fn new(queue: Rc<RefCell<MessageQueue>>, channel: Channel, waitpoint: Waitpoint) -> Self {
        Self {
            queue,
            channel,
            waitpoint,
        }
    }
}

impl Future for MessageQueueWait {
    type Output = (Participant, MessageData);

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.queue.borrow_mut().pop(self.channel, self.waitpoint) {
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
    pub async fn send_many<T: Serialize>(&self, channel: Channel, waitpoint: Waitpoint, data: &T) {
        let message_data = encode_with_tag((channel, waitpoint), data);
        self.send_raw(Message::Many(message_data)).await;
    }

    /// (Indicate that you want to) send a message privately to everybody else.
    pub async fn send_private<T: Serialize>(
        &self,
        channel: Channel,
        waitpoint: Waitpoint,
        to: Participant,
        data: &T,
    ) {
        let message_data = encode_with_tag((channel, waitpoint), data);
        self.send_raw(Message::Private(to, message_data)).await;
    }

    /// Get the next wait point for communications.
    pub fn next_waitpoint(&self, chan: Channel) -> u8 {
        self.queue.borrow_mut().next_waitpoint(chan) as u8
    }
    ///
    /// Get the next channel for communications.
    pub fn next_channel(&self) -> u8 {
        self.queue.borrow_mut().next_channel() as u8
    }

    /// Receive a message for a specific round.
    pub async fn recv<T: DeserializeOwned>(
        &self,
        channel: Channel,
        waitpoint: Waitpoint,
    ) -> Result<(Participant, T), ProtocolError> {
        let (from, data) = MessageQueueWait::new(self.queue.clone(), channel, waitpoint).await;
        // We know data will be at least one byte long
        let decoded: Result<T, Box<dyn error::Error>> = decode(&data[2..]).map_err(|e| e.into());
        Ok((from, decoded?))
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
