//! This module holds some utilities for working with participants.
//!
//! Often you need to do things like, storing one item for each participant,
//! or getting the field values corresponding to each participant, etc.
//! This module tries to provide useful data structures for doing that.

use std::collections::HashMap;

use serde::Serialize;

use crate::protocol::Participant;

/// Represents a sorted list of participants.
///
/// The advantage of this data structure is that it can be hashed in the protocol transcript,
/// since everybody will agree on its order.
#[derive(Debug, Serialize)]
pub struct ParticipantList {
    participants: Vec<Participant>,
    /// This maps each participant to their index in the vector above.
    #[serde(skip_serializing)]
    indices: HashMap<Participant, usize>,
}

impl ParticipantList {
    /// Create a participant list from a slice of participants.
    pub fn new(participants: &[Participant]) -> Self {
        let mut out = participants.to_owned();
        out.sort();

        let indices = out.iter().enumerate().map(|(p, x)| (*x, p)).collect();

        Self {
            participants: out,
            indices,
        }
    }
}

/// A map from participants to elements.
///
/// The idea is that you have one element for each participant.
#[derive(Debug, Clone, Serialize)]
pub struct ParticipantMap<'a, T> {
    #[serde(skip_serializing)]
    participants: &'a ParticipantList,
    data: Vec<Option<T>>,
    #[serde(skip_serializing)]
    count: usize,
}

impl<'a, T> ParticipantMap<'a, T> {
    /// Create a new map from a list of participants.
    ///
    /// This map only lives as long as that list of participants.
    pub fn new(participants: &'a ParticipantList) -> Self {
        // We could also require a T: Clone bound instead of doing this initialization manually.
        let size = participants.participants.len();
        let mut data = Vec::with_capacity(size);
        for _ in 0..size {
            data.push(None);
        }

        Self {
            participants,
            data,
            count: 0,
        }
    }

    /// Check if this map is full, i.e. if every participant has put something in.
    pub fn full(&self) -> bool {
        self.count == self.data.len()
    }

    /// Check if this map contains data from a specific participant.
    pub fn contains(&mut self, participant: Participant) -> bool {
        let i = self.participants.indices.get(&participant);
        if i.is_none() {
            return false;
        }
        let i = *i.unwrap();
        self.data[i].is_some()
    }

    /// Place the data for a participant in this map.
    ///
    /// This will assert that not data for that participant already exists,
    /// so upstream consumers should check this condition somehow.
    pub fn put(&mut self, participant: Participant, data: T) {
        let i = self.participants.indices.get(&participant);
        if i.is_none() {
            return;
        }
        let i = *i.unwrap();

        assert!(self.data[i].is_none());

        self.data[i] = Some(data);
    }
}