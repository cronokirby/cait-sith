use super::{MessageData, Participant};

/// Represents a queue of messages.
///
/// This is used to receive incoming messages as they arrive, and automatically
/// sort them into bins based on
#[derive(Debug, Clone)]
pub struct MessageQueue {
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
    pub fn new(waitpoints: usize, parties_hint: usize) -> Self {
        Self {
            stacks: vec![Vec::with_capacity(parties_hint.saturating_sub(1)); waitpoints],
        }
    }

    /// The number of waitpoints in this queue.
    pub fn waitpoints(&self) -> usize {
        self.stacks.len()
    }

    /// Push a new message into the queue.
    ///
    /// This will read the first byte of the message to determine what round it
    /// belongs to.
    pub fn push(&mut self, from: Participant, message: MessageData) {
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
    pub fn pop(&mut self, round: usize) -> Option<(Participant, MessageData)> {
        assert!(round < self.stacks.len());

        self.stacks[round].pop()
    }
}
