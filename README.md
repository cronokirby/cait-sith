# Cait-Sith [![](https://img.shields.io/crates/v/cait-sith.svg)](https://crates.io/crates/cait-sith) [![](https://docs.rs/cait-sith/badge.svg)](https://docs.rs/cait-sith)

Cait-Sith is a novel threshold ECDSA protocol (and implementation),
which is both simpler and substantially more performant than
popular alternatives.

The protocol supports arbitrary numbers of parties and thresholds.

<img
 width="33%"
 align="right"
 src="./logo.png"/>

# Warning

This is experimental cryptographic software, unless you're a cat with
a megaphone on top of a giant Moogle I would exercise caution.

- The protocol does not have a formal proof of security.
- This library has not undergone any form of audit.

# Design

The main design principle of Cait-Sith is offloading as much work
to a key-independent preprocessing phase as possible.
The advantage of this approach is that this preprocessing phase can be conducted
in advance, before a signature is needed, and the results of this phase
can even be peformed before the key that you need to sign with is decided.

One potential scenario where this is useful is when running a threshold
custody service over many keys, where these preprocessing results
can be performed, and then used on demand regardless of which keys
end up being used more often.

A detailed specification is available [in this repo](./docs),
but we'll also give a bit of detail here.

The core of Cait-Sith's design involves a *committed* Beaver triple.
These are of the form:

$$
([a], [b], [c]), (A = a \cdot G, B = b \cdot G, C = c \cdot G)
$$

where $a, b, c$ are scalars such that $a \cdot b = c$, and are
secret shared among several participants, so that no one knows their actual value.
Furthermore, unlike standard Beaver triples, we also have a public commitment
to the these secret values, which helps the online protocol.

The flow of the protocol is first that the parties need a way to generate triples:

- A setup protocol is run once, allowing parties to efficiently generate triples.
- The parties can now generate an arbitrary number triples through a distributed protocol.

Then, the parties need to generate a key pair so that they can sign messages:

- The parties run a distributed key generation protocol to setup a new key pair,
which can be used for many signatures.

When the parties want to sign using a given key:

- Using their shares of a private key, the parties can create a *presignature*,
before knowing the message to sign.
- Once they know this message, they can use the presignature to create a complete signature.

It's important that presignatures and triples are **never** reused.

## API Design

Internally, the API tries to be as simple as possible abstracting away
as many details as possible into a simple interface.

This interface just has two methods:
```rust
pub trait Protocol {
    type Output;

    fn poke(&mut self) -> Result<Action<Self::Output>, ProtocolError>;
    fn message(&mut self, from: Participant, data: MessageData);
}
```
Given an instance of this trait, which represents a single party
participating in a protocol, you can do two things:
- You can provide a new message received from some other party.
- You can "poke" the protocol to see if it has some kind of action it wants you to perform, or if an error happened.

This action is either:
- The protocol telling you it has finished, with a return value of type `Output`.
- The protocol asking you to send a message to all other parties.
- The protocol asking you to *privately* send a message to one party.
- The protocol informing you that no more progress can be made until it receives new messages.

In particular, details about rounds and message serialization are abstracted
away, and all performed internally.
In fact, the protocols aren't designed around "rounds", and can even have parallel
threads of execution internally for some of the more complicated ones.

# Benchmarks

Here are some benchmarks, performed on an Intel Core i5-4690K CPU.

```
setup 3
time:   [94.689 ms 95.057 ms 95.449 ms]

triple generation (3, 3)
time:   [36.610 ms 36.682 ms 36.757 ms]

keygen (3,3)
time:   [3.0901 ms 3.1095 ms 3.1297 ms]

presign (3,3)
time:   [2.5531 ms 2.5640 ms 2.5761 ms]

sign (3,3)
time:   [446.79 µs 447.89 µs 449.02 µs]
```

These were performed with 3 parties running on the same machine,
with no communication cost.

Note that triple generation needs to be performed *twice* for each signature.
Also, triple generation is relatively bandwidth intensive compared to other
protocols, which isn't reflected in these benchmarks, since network speed
isn't constrained.
Nonetheless, this cost isn't all that important, because it can be performed
in advance, and independent of the key.

Thus, the cost of presigning + signing should be considered instead.
This cost is low enough to be bottlenecked by network performance, most likely.

# Shortcomings

The protocol and its implementation do have a few known disadvantages at the moment:

- The protocol does require generating triples in advance, but these can be generated without knowledge of the private key.
- The protocol does not attempt to provide identifiable aborts.
- At the moment, the library only supports Secp256k1 as the curve and SHA256 as the hash, but we plan on adding support for arbitrary curves and hashes.
- The library also doesn't have an explicit refresh protocol, although we plan on adding this.

We also don't really intend to add identifiable aborts to Cait-Sith itself.
While these can be desirable in certain situations, we aren't satisfied
with the way the property of identifiable aborts is modeled currently,
and are working on improvements to this model.
