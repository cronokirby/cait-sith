use std::io::Write;

use ck_meow::Meow;
use serde::{Deserialize, Serialize};

use crate::serde::encode_writer;

const COMMIT_LABEL: &[u8] = b"cait-sith v0.1.0 commitment";
const COMMIT_LEN: usize = 32;

struct MeowWriter<'a>(&'a mut Meow);

impl<'a> Write for MeowWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.ad(buf, true);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Represents a commitment to some value.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment([u8; COMMIT_LEN]);

impl AsRef<[u8]> for Commitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Commit to an arbitrary serializable value.
pub fn commit<T: Serialize>(val: &T) -> Commitment {
    let mut meow = Meow::new(COMMIT_LABEL);

    meow.ad(&[], false);
    encode_writer(&mut MeowWriter(&mut meow), val);

    let mut out = [0u8; COMMIT_LEN];
    meow.prf(&mut out, false);

    Commitment(out)
}
