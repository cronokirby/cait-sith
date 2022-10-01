use core::fmt;
use std::error;

/// Represents an error which can happen when running a protocol.
#[derive(Debug)]
pub enum ProtocolError {
    /// Some generic error happened.
    Other(Box<dyn error::Error>),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::Other(e) => write!(f, "{}", e),
        }
    }
}

impl error::Error for ProtocolError {}

impl Into<ProtocolError> for Box<dyn error::Error> {
    fn into(self) -> ProtocolError {
        ProtocolError::Other(self)
    }
}

/// Represents a participant in the protocol.
///
/// Each participant should be uniquely identified by some number, which this
/// struct holds. In our case, we use a `u32`, which is enough for billions of
/// participants. That said, you won't actually be able to make the protocols
/// work with billions of users.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Participant(u32);

impl Into<Participant> for u32 {
    fn into(self) -> Participant {
        Participant(self)
    }
}

impl Into<u32> for Participant {
    fn into(self) -> u32 {
        self.0
    }
}

/// Represents the data making up a message.
///
/// We choose to just represent messages as opaque vectors of bytes, with all
/// the serialization logic handled internally.
pub type MessageData = Vec<u8>;

/// Represents an action by a participant in the protocol.
///
/// The basic flow is that each participant receives messages from other participants,
/// and then reacts with some kind of action.
///
/// This action can consist of sending a message, doing nothing, etc.
///
/// Eventually, the participant returns a value, ending the protocol.
#[derive(Debug, Clone)]
pub enum Action<T> {
    /// Don't do anything.
    Wait,
    /// Send a message to all other participants.
    ///
    /// Participants *never* sends messages to themselves.
    SendMany(MessageData),
    /// Send a private message to another participant.
    ///
    /// It's imperactive that only this participant can read this message,
    /// so you might want to use some form of encryption.
    SendPrivate(Participant, MessageData),
    /// End the protocol by returning a value.
    Return(T),
}

/// A trait for protocols.
///
/// Basically, this represents a struct for the behavior of a single participant
/// in a protocol. The idea is that the computation of that participant is driven
/// mainly by receiving messages from other participants.
pub trait Protocol {
    type Output;

    /// Start the execution of the protocol, returning the action of this participant.
    fn start(&mut self) -> Result<Action<Self::Output>, ProtocolError>;

    /// Advance this protocol with a message from some participant.
    fn advance(
        &mut self,
        from: Participant,
        data: MessageData,
    ) -> Result<Action<Self::Output>, ProtocolError>;
}

pub(crate) mod internal;
