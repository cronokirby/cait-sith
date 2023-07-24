//! This module holds some utilities for working with participants.
//!
//! Often you need to do things like, storing one item for each participant,
//! or getting the field values corresponding to each participant, etc.
//! This module tries to provide useful data structures for doing that.

use std::{collections::HashMap, mem, ops::Index};

use elliptic_curve::Field;
use serde::Serialize;

use crate::{compat::CSCurve, protocol::Participant};

/// Represents a sorted list of participants.
///
/// The advantage of this data structure is that it can be hashed in the protocol transcript,
/// since everybody will agree on its order.
#[derive(Clone, Debug, Serialize)]
pub struct ParticipantList {
    participants: Vec<Participant>,
    /// This maps each participant to their index in the vector above.
    #[serde(skip_serializing)]
    indices: HashMap<Participant, usize>,
}

impl ParticipantList {
    // For optimization reasons, another method needs this.
    fn new_vec(mut participants: Vec<Participant>) -> Option<Self> {
        participants.sort();

        let indices: HashMap<_, _> = participants
            .iter()
            .enumerate()
            .map(|(p, x)| (*x, p))
            .collect();

        if indices.len() < participants.len() {
            return None;
        }

        Some(Self {
            participants,
            indices,
        })
    }

    /// Create a participant list from a slice of participants.
    ///
    /// This will return None if the participants have duplicates.
    pub fn new(participants: &[Participant]) -> Option<Self> {
        Self::new_vec(participants.to_owned())
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
        self.participants.iter().filter(move |x| **x != me).copied()
    }

    /// Return the index of a given participant.
    ///
    /// Basically, the order they appear in a sorted list
    pub fn index(&self, participant: Participant) -> usize {
        self.indices[&participant]
    }

    /// Get the lagrange coefficient for a participant, relative to this list.
    pub fn lagrange<C: CSCurve>(&self, p: Participant) -> C::Scalar {
        let p_scalar = p.scalar::<C>();

        let mut top = C::Scalar::ONE;
        let mut bot = C::Scalar::ONE;
        for q in &self.participants {
            if p == *q {
                continue;
            }
            let q_scalar = q.scalar::<C>();
            top *= q_scalar;
            bot *= q_scalar - p_scalar;
        }

        top * bot.invert().unwrap()
    }

    /// Return the intersection of this list with another list.
    pub fn intersection(&self, others: &ParticipantList) -> Self {
        let mut out = Vec::new();
        for &p in &self.participants {
            if others.contains(p) {
                out.push(p);
            }
        }
        // We know that no duplicates will be created, so unwrapping is safe
        Self::new_vec(out).unwrap()
    }
}

impl From<ParticipantList> for Vec<Participant> {
    fn from(val: ParticipantList) -> Self {
        val.participants
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

    /// Place the data for a participant in this map.
    ///
    /// This will do nothing if the participant is unknown, or already has a value
    pub fn put(&mut self, participant: Participant, data: T) {
        let i = self.participants.indices.get(&participant);
        if i.is_none() {
            return;
        }
        let i = *i.unwrap();

        if self.data[i].is_some() {
            return;
        }

        self.data[i] = Some(data);
        self.count += 1;
    }
}

impl<'a, T> Index<Participant> for ParticipantMap<'a, T> {
    type Output = T;

    fn index(&self, index: Participant) -> &Self::Output {
        self.data[self.participants.index(index)].as_ref().unwrap()
    }
}

/// A way to count participants.
///
/// This is used when you want to process a message from each participant only once.
/// This datastructure will let you put a participant in, and then tell you if this
/// participant was newly inserted or not, allowing you to thus process the
/// first message received from them.
#[derive(Debug, Clone)]
pub struct ParticipantCounter<'a> {
    participants: &'a ParticipantList,
    seen: Vec<bool>,
    counter: usize,
}

impl<'a> ParticipantCounter<'a> {
    /// Create a new participant counter from the list of all participants.
    pub fn new(participants: &'a ParticipantList) -> Self {
        Self {
            participants,
            seen: vec![false; participants.len()],
            counter: participants.len(),
        }
    }

    /// Put a new participant in this counter.
    ///
    /// This will return true if the participant was added, or false otherwise.
    ///
    /// The participant may not have been added because:
    /// - The participant is not part of our participant list.
    /// - The participant has already been added.
    ///
    /// This can be checked to not process a message twice.
    pub fn put(&mut self, participant: Participant) -> bool {
        let i = match self.participants.indices.get(&participant) {
            None => return false,
            Some(&i) => i,
        };

        // Need the old value to be false.
        let inserted = !mem::replace(&mut self.seen[i], true);
        if inserted {
            self.counter -= 1;
        }
        inserted
    }

    /// Clear the contents of this counter.
    pub fn clear(&mut self) {
        for x in &mut self.seen {
            *x = false
        }
        self.counter = self.participants.len();
    }

    /// Check if this counter contains all participants
    pub fn full(&self) -> bool {
        self.counter == 0
    }
}
