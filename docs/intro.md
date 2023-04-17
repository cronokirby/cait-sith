These docs provide a lower level description of the protocols used in Cait-Sith.

# Overview

## [Orchestration](./orchestration.md)

Describes how the different protocols fit together.

## [Proofs](./proofs.md)

Describes the conventions around transcripts and ZK Proofs.

## [Key Generation](./key-generation.md)

This describes the distributed key generation protocol.

## [Triples](./triples.md)

This describes the triple generation protocol: a pre-processing phase
used to speed up signing.

## [Signing](./signing.md)

This describes the signing protocol, which consists of a presignature phase
and a final signature phase.

# Security Analysis

A security analysis of the protocol is available [here](https://cronokirby.com/notes/2023/04/cait-sith-security/).

# Some Notation conventions

Vectors / Matrices are denoted $x_i$ or $A_{ij}$, using indices. Operators behave pointwise. For example, $x_i \cdot y_i$ creates a new vector by multiplying the entries of $x$ and $y$ pointwise. $\langle A_{ij}, \ldots \rangle$ denotes summation, over the shared indices. For example $\langle A_{ij}, x_j \rangle_i$ would be $A x$ in more conventional matrix vector multiplication notation.

$\lambda(\mathcal{P})_i$ denotes the Lagrange coefficient for participant $i$
in a group of participants $\mathcal{P}$, used for interpolating threshold
shared values into linear shared values.
