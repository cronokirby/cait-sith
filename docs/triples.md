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

The first protocol we make use of is *random oblivious transfer*.
This is a two-party protocol, involving a sender $\mathcal{S}$, and a receiver $\mathcal{R}$.
The receiver has as input a bit $b$.

The output of the protocol if a trusted dealer existed would be:
$$
\begin{aligned}
&k_ 0, k_ 1 \xleftarrow{\$} \\\{0, 1\\\}^\lambda\cr
&\mathcal{R} \texttt{ gets } k_ b\cr
&\mathcal{S} \texttt{ gets } k_ 0, k_ 1\cr
\end{aligned}
$$

The seed length $\lambda$ is the ambient security parameter.
(e.g. 128 bits, in the usual case)

In particular, we consider a *batched* version of this functionality,
in which the receiver has $l$ bits $b_ 1, \ldots, b_ l$, and both parties.
Receive the output $l$ times.

We can also consider the result as being two matrices $K_{ij}^0$ and $K_{ij}^1$,
with $i \in [l]$, $j \in [\lambda]$,
with the receiver getting the matrix $K_ {ij}^{b_ i}$.

## "Simplest" OT Protocol

For batch random OT, we use the so-called "simplest" OT Protocol
[[CO15]](https://eprint.iacr.org/2015/267).

Procotol `Batch-Random-OT`:

1. $\mathcal{S}$ samples $y \xleftarrow{R} \mathbb{F}_q$, and sets $Y \gets y \cdot G$, and $Z \gets y \cdot Y$.
2. $\star$ $\mathcal{S}$ sends $Y$ to $\mathcal{R}$.
3. $\bullet$ $\mathcal{R}$ waits to receive $Y$.

In parallel, for $i \in [l]$:

4. $\mathcal{R}$ samples $x_i \xleftarrow{R} \mathbb{F}_q$, and computes $X_i \gets b_i \cdot Y + x_i \cdot G$.
5. $\mathcal{R}$ computes $K_{ij}^{b_ i} \gets H_{(i, Y, X_ i)}(x_ i \cdot Y)$
6. $\star$ $\mathcal{R}$ sends $X_i$ to $\mathcal{S}$.
7. $\bullet$ $\mathcal{S}$ waits to receive $X_i$.
8. $\mathcal{S}$ computes $K_{ij}^b \gets H_{(i, Y, X_ i)}(y \cdot X_ i - b \cdot Z)_j$.

Here $H$ is a hash function, parameterized by an integer $i$, as well
as two points, providing a key derivation function $\mathbb{G} \to \mathbb{F}_2^{\lambda}$.

# Setup Phase

The goal of the setup phase is for each ordered pair of parties $\mathcal{P}_a$
and $\mathcal{P}_b$ to run a $\lambda$ batched random OT.
Each pair will be run twice, with one party being the sender in one instance,
and the other party being the sender in the other.

The end result is that $\mathcal{P}_a$ will learn $K_{ij}^0$ and $K_{ij}^1$,
and $\mathcal{P}_b$ will learn $K_{ij}^{\Delta_ i}$, for a randomly chosen $\Delta \in \mathbb{F}_2^{\lambda}$.

In more detail:

Protocol `Triples-Setup`

In parallel, for each ordered pair of parties $\mathcal{P}_a$ and $\mathcal{P}_b$
$\mathcal{P}_b$ samples $\Delta \xleftarrow{R} \mathbb{F}_2^\lambda$,
and then $\mathcal{P}_a$ and $\mathcal{P}_b$ run `Batch-Random-OT` with a batch size
of $\lambda$, and save the result.

# Extended Oblivious Transfer

# Multiplicative to Additive Conversion

# Multiplication

# Triple Generation

