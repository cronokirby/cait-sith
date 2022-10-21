This document specifies the protocol for triple generation.
Note that while the other specifications and parts of the protocol are intended
to be strictly followed, this specification is less opinionated about generating
triples.

As long as valid triples are generated according to proces, they
can be used in the subsequent presigning phase.
The presigning phase is agnostic as to how these triples have been generated.

This document only gives a very concrete suggestion as to how this might be implemented,
and describes how this crate implements triple generation without a trusted
dealer.

Compared to the other parts of the protocol, triple generation is more complex,
in that it involves the composition of several layers of protocols.
We describe each of these from the bottom up.

# Random Oblivious Transfer

# Extended Oblivious Transfer

# Multiplicative to Additive Conversion

# Multiplication

# Triple Generation

