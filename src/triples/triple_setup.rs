use std::collections::HashMap;

use crate::{participants::ParticipantList, protocol::Participant};

use super::bits::{BitVector, SquareBitMatrix};

/// Represents a single setup, allowing for random OT extensions later.
///
/// These random OT extensions will be used for generating triples.
///
/// The names of the variants refer to the roles each party plays in the
/// extension.
#[derive(Debug, Clone)]
pub enum SingleSetup {
    Sender(BitVector, SquareBitMatrix),
    Receiver(SquareBitMatrix, SquareBitMatrix),
}

/// Represents the setup we need for generating triples efficiently later.
///
/// This consists of a single setup for each other party in a list of participants.
#[derive(Debug, Clone)]
pub struct Setup {
    setups: HashMap<Participant, SingleSetup>,
}

impl Setup {
    /// This returns true if this setup can be used for a given list of participants.
    ///
    /// This will check that the setup has sufficient information for these participants.
    pub fn can_be_used_for(&self, me: Participant, participants: &ParticipantList) -> bool {
        participants
            .others(me)
            .all(|p| self.setups.contains_key(&p))
    }
}
