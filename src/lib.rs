mod compat;
mod constants;
mod crypto;
mod keygen;
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

pub use keygen::{keygen, KeygenOutput};
pub use presign::{presign, PresignArguments, PresignOutput};
pub use sign::{sign, FullSignature};
pub use triples::{
    generate_triple, setup, Setup, SingleSetup, TripleGenerationOutput, TriplePub, TripleShare,
};
