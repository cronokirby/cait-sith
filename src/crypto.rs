use std::io::Write;

use ck_meow::Meow;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::serde::encode_writer;

const COMMIT_LABEL: &[u8] = b"cait-sith v0.8.0 commitment";
const COMMIT_LEN: usize = 32;
const RANDOMIZER_LEN: usize = 32;
const HASH_LABEL: &[u8] = b"cait-sith v0.8.0 generic hash";
const HASH_LEN: usize = 32;

struct MeowWriter<'a>(&'a mut Meow);

impl<'a> MeowWriter<'a> {
    fn init(meow: &'a mut Meow) -> Self {
        meow.ad(&[], false);
        Self(meow)
    }
}

impl<'a> Write for MeowWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.ad(buf, true);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Represents the randomizer used to make a commit hiding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Randomizer([u8; RANDOMIZER_LEN]);

impl Randomizer {
    /// Generate a new randomizer value by sampling from an RNG.
    fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut out = [0u8; RANDOMIZER_LEN];
        rng.fill_bytes(&mut out);
        Self(out)
    }
}

impl AsRef<[u8]> for Randomizer {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Represents a commitment to some value.
///
/// This commit is both binding, in that it can't be opened to a different
/// value than the one committed, and hiding, in that it hides the value
/// committed inside (perfectly).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment([u8; COMMIT_LEN]);

impl Commitment {
    fn compute<T: Serialize>(val: &T, r: &Randomizer) -> Self {
        let mut meow = Meow::new(COMMIT_LABEL);

        meow.ad(r.as_ref(), false);
        meow.meta_ad(b"start data", false);
        encode_writer(&mut MeowWriter::init(&mut meow), val);

        let mut out = [0u8; COMMIT_LEN];
        meow.prf(&mut out, false);

        Commitment(out)
    }

    /// Check that a value and a randomizer match this commitment.
    #[must_use]
    pub fn check<T: Serialize>(&self, val: &T, r: &Randomizer) -> bool {
        let actual = Self::compute(val, r);
        *self == actual
    }
}

/// Commit to an arbitrary serializable value.
///
/// This also returns a fresh randomizer, which is used to make sure that the
/// commitment perfectly hides the value contained inside.
///
/// This value will need to be sent when opening the commitment to allow
/// others to check that the opening is valid.
pub fn commit<T: Serialize, R: CryptoRngCore>(rng: &mut R, val: &T) -> (Commitment, Randomizer) {
    let r = Randomizer::random(rng);
    let c = Commitment::compute(val, &r);
    (c, r)
}

/// The output of a generic hash function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Digest([u8; HASH_LEN]);

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Hash some value to produce a short digest.
pub fn hash<T: Serialize>(val: &T) -> Digest {
    let mut meow = Meow::new(HASH_LABEL);
    encode_writer(&mut MeowWriter::init(&mut meow), val);

    let mut out = [0u8; HASH_LEN];
    meow.prf(&mut out, false);

    Digest(out)
}
