//! Cait-Sith is a novel threshold ECDSA protocol (and implementation),
//! which is both simpler and substantially more performant than
//! popular alternatives.
//!
//! The protocol supports arbitrary numbers of parties and thresholds.
//!
//! # Warning
//!
//! This is experimental cryptographic software, unless you're a cat with
//! a megaphone on top of a giant Moogle I would exercise caution.
//!
//! - The protocol does not have a formal proof of security.
//! - This library has not undergone any form of audit.
//!
//! # Design
//!
//! The main design principle of Cait-Sith is offloading as much work
//! to a key-independent preprocessing phase as possible.
//! The advantage of this approach is that this preprocessing phase can be conducted
//! in advance, before a signature is needed, and the results of this phase
//! can even be peformed before the key that you need to sign with is decided.
//!
//! One potential scenario where this is useful is when running a threshold
//! custody service over many keys, where these preprocessing results
//! can be performed, and then used on demand regardless of which keys
//! end up being used more often.
//!
//! A detailed specification is available [in this repo](./docs),
//! but we'll also give a bit of detail here.
//!
//! The core of Cait-Sith's design involves a *committed* Beaver triple.
//! These are of the form:
//! ```ignore
//! ([a], [b], [c]), (A = a * G, B = b * G, C = c * G)
//! ```
//! where `a, b, c` are scalars such that `a * b = c`, and are
//! secret shared among several participants, so that no one knows their actual value.
//! Furthermore, unlike standard Beaver triples, we also have a public commitment
//! to the these secret values, which helps the online protocol.
//!
//! The flow of the protocol is first that the parties need a way to generate triples:
//!
//! - A setup protocol is run once, allowing parties to efficiently generate triples.
//! - The parties can now generate an arbitrary number triples through a distributed protocol.
//!
//! Then, the parties need to generate a key pair so that they can sign messages:
//!
//! - The parties run a distributed key generation protocol to setup a new key pair,
//! which can be used for many signatures.
//!
//! When the parties want to sign using a given key:
//!
//! - Using their shares of a private key, the parties can create a *presignature*,
//! before knowing the message to sign.
//! - Once they know this message, they can use the presignature to create a complete signature.
//!
//! It's important that presignatures and triples are **never** reused.
//!
//! ## API Design
//!
//! Internally, the API tries to be as simple as possible abstracting away
//! as many details as possible into a simple interface.
//!
//! This interface just has two methods:
//! ```ignore
//! pub trait Protocol {
//!    type Output;
//!
//!    fn poke(&mut self) -> Result<Action<Self::Output>, ProtocolError>;
//!    fn message(&mut self, from: Participant, data: MessageData);
//! }
//! ```
//! Given an instance of this trait, which represents a single party
//! participating in a protocol, you can do two things:
//! - You can provide a new message received from some other party.
//! - You can "poke" the protocol to see if it has some kind of action it wants you to perform, or if an error happened.
//!
//! This action is either:
//! - The protocol telling you it has finished, with a return value of type `Output`.
//! - The protocol asking you to send a message to all other parties.
//! - The protocol asking you to *privately* send a message to one party.
//! - The protocol informing you that no more progress can be made until it receives new messages.
//!
//! In particular, details about rounds and message serialization are abstracted
//! away, and all performed internally.
//! In fact, the protocols aren't designed around "rounds", and can even have parallel
//! threads of execution internally for some of the more complicated ones.
//! # Generic Curves
//!
//! The library has support for generic curves and hashes.
//!
//! The support for generic curves is done through a custom `CSCurve` trait,
//! which can be easily implemented for any curve from the
//! RustCrypto [elliptic-curves](https://github.com/RustCrypto/elliptic-curves)
//! suite of libraries.
//!
//! This crate also provides implementations of some existing curves behind features,
//! as per the following table:
//!
//! | Curve | Feature |
//! |-------|---------|
//! |Secp256k1|`k256`|
//!
//! For supporting any message hash, the API requires the user to supply
//! the hash of a message when signing as a scalar directly.
//!
//! # Shortcomings
//!
//! The protocol and its implementation do have a few known disadvantages at the moment:
//!
//! - The protocol does require generating triples in advance, but these can be generated without knowledge of the private key.
//! - The protocol does not attempt to provide identifiable aborts.
//!
//! We also don't really intend to add identifiable aborts to Cait-Sith itself.
//! While these can be desirable in certain situations, we aren't satisfied
//! with the way the property of identifiable aborts is modeled currently,
//! and are working on improvements to this model.
mod compat;
mod constants;
mod crypto;
mod keyshare;
mod math;
mod participants;
mod presign;
mod proofs;
pub mod protocol;
mod serde;
mod sign;
#[cfg(test)]
mod test;
pub mod triples;

pub use compat::CSCurve;
pub use keyshare::{keygen, refresh, reshare, KeygenOutput};
pub use presign::{presign, PresignArguments, PresignOutput};
pub use sign::{sign, FullSignature};
