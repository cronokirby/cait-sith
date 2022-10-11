use std::{
    cell::RefCell,
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

/// Represents a queue of messages.
///
/// This is used to receive incoming messages as they arrive, and automatically
/// sort them into bins based on
#[derive(Debug, Clone)]
struct MessageQueue {
    /// We have one stack of messages for each round / wait point.
    stacks: Vec<Vec<(Participant, MessageData)>>,
}

impl MessageQueue {
    /// Create a new message queue, given a number of wait points.
    ///
    /// Each wait point is a distinct point in the protocol where we'll wait
    /// for a message.
    ///
    /// We also take in a hint for the number of parties participating in the protocol.
    /// This just allows us to pre-allocate buffers of the right size, and is just
    /// a performance optimization.
    fn new(waitpoints: usize, parties_hint: usize) -> Self {
        Self {
            stacks: vec![Vec::with_capacity(parties_hint.saturating_sub(1)); waitpoints],
        }
    }

    /// Push a new message into the queue.
    ///
    /// This will read the first byte of the message to determine what round it
    /// belongs to.
    fn push(&mut self, from: Participant, message: MessageData) {
        if message.is_empty() {
            return;
        }

        let round = usize::from(message[0]);
        if round >= self.stacks.len() {
            return;
        }

        self.stacks[round].push((from, message));
    }

    /// Pop a message from a specific round.
    ///
    /// This round **must** be less than the number of waitpoints of this queue.
    fn pop(&mut self, round: usize) -> Option<(Participant, MessageData)> {
        assert!(round < self.stacks.len());

        self.stacks[round].pop()
    }
}

/// A future which tries to read a message from a specific round.
struct MessageQueueWait {
    queue: Rc<RefCell<MessageQueue>>,
    round: usize,
}

impl MessageQueueWait {
    fn new(queue: Rc<RefCell<MessageQueue>>, round: usize) -> Self {
        Self { queue, round }
    }
}

impl Future for MessageQueueWait {
    type Output = (Participant, MessageData);

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.queue.borrow_mut().pop(self.round) {
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
    /// Create new communications, given a number of waitpoints, and parties.
    ///
    /// The latter is just a hint for performance.
    ///
    /// The former is more meaningful, as it indicates which messages will be ignored.
    /// Messages have a tag encoded into them, indicating the round they're sent
    /// for. If a message gets sent to a round beyond the number of expected waitpoints,
    /// that message is dropped. Thus, it's important for the number of waitpoints
    /// to be correct.
    pub fn new(waitpoints: usize, parties_hint: usize) -> Self {
        let queue = MessageQueue::new(waitpoints, parties_hint);
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
    pub async fn send_many<T: Serialize>(&self, round: u8, data: &T) {
        let message_data = encode_with_tag(round, data);
        self.send_raw(Message::Many(message_data)).await;
    }

    /// (Indicate that you want to) send a message privately to everybody else.
    pub async fn send_private<T: Serialize>(&self, round: u8, to: Participant, data: &T) {
        let message_data = encode_with_tag(round, data);
        self.send_raw(Message::Private(to, message_data)).await;
    }

    /// Receive a message for a specific round.
    pub async fn recv<T: DeserializeOwned>(
        &self,
        round: u8,
    ) -> Result<(Participant, T), ProtocolError> {
        let (from, data) = MessageQueueWait::new(self.queue.clone(), usize::from(round)).await;
        // We know data will be at least one byte long
        let decoded: Result<T, Box<dyn error::Error>> = decode(&data[1..]).map_err(|e| e.into());
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
