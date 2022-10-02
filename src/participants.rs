//! This module holds some utilities for working with participants.
//!
//! Often you need to do things like, storing one item for each participant,
//! or getting the field values corresponding to each participant, etc.
//! This module tries to provide useful data structures for doing that.

use std::{collections::HashMap, ops::Index};

use k256::Scalar;
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
    #[serde(skip_serializing)]
    domain: Vec<Scalar>,
}

impl ParticipantList {
    /// Create a participant list from a slice of participants.
    ///
    /// This will return None if the participants have duplicates.
    pub fn new(participants: &[Participant]) -> Option<Self> {
        let mut out = participants.to_owned();
        out.sort();

        let indices: HashMap<_, _> = out.iter().enumerate().map(|(p, x)| (*x, p)).collect();

        if indices.len() < out.len() {
            return None;
        }

        let mut domain = Vec::with_capacity(participants.len() + 1);
        domain.push(Scalar::ZERO);
        for &p in participants {
            domain.push(p.scalar());
        }

        Some(Self {
            participants: out,
            indices,
            domain,
        })
    }

    pub fn len(&self) -> usize {
        self.participants.len()
    }

    /// Check if this list has a given participant.
    pub fn contains(&self, participant: Participant) -> bool {
        self.indices.contains_key(&participant)
    }

    /// Iterate over the other participants
    pub fn others(&self, me: Participant) -> impl Iterator<Item = Participant> + '_ {
        self.participants
            .iter()
            .filter(move |x| **x != me)
            .map(|x| *x)
    }

    /// Return the index of a given participant.
    ///
    /// Basically, the order they appear in a sorted list
    pub fn index(&self, participant: Participant) -> usize {
        self.indices[&participant]
    }

    /// Get the evaluation domain.
    ///
    /// This will include the scalar for each participant, preceded by 0.
    ///
    /// This will not be calculated every time, but cached.
    pub fn domain(&self) -> &[Scalar] {
        &self.domain
    }

    /// Get the lagrange coefficient for a participant, relative to this list.
    pub fn lagrange(&self, p: Participant) -> Scalar {
        let p_scalar = p.scalar();
        let p_i = self.index(p) + 1;

        let mut acc = Scalar::ONE;
        for (i, &s) in self.domain.iter().enumerate() {
            if i == p_i || i == 0 {
                continue;
            }
            acc *= p_scalar - s;
        }

        p_scalar * acc.invert().unwrap()
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

impl<'a, T> Index<Participant> for ParticipantMap<'a, T> {
    type Output = T;

    fn index(&self, index: Participant) -> &Self::Output {
        self.data[self.participants.index(index)].as_ref().unwrap()
    }
}
