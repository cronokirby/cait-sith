mod crypto;
mod compat;
mod keygen;
mod math;
mod participants;
mod presign;
mod proofs;
pub mod protocol;
mod serde;
pub mod triples;
mod sign;
#[cfg(test)]
mod test;

pub use sign::{sign, FullSignature};
pub use presign::{presign, PresignOutput, PresignArguments};
pub use keygen::{keygen, KeygenOutput};