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
Note that communication in this subprotocol should be *private*.

# Extended Oblivious Transfer

The goal of the extended oblivious transfer protocol is for two parties
to extend their joint setup, and use that setup to generate $\kappa$ oblivious
transfers, using fast symmetric key primitives.

## Correlated OT Extension

We start with the *correlated* extension protocol.

The correlation comes from the $\Delta$ value used in the setup, controlled
by the sender $\mathcal{S}$.
Note that the sender was the receiver in the original setup.
In this protocol $\mathcal{R}$ uses an input matrix $X_{ij}$, and learns a random boolean matrix
$T_{ij} \in \mathbb{F}_2$, $i \in [\kappa], j \in [\lambda]$,
and $\mathcal{S}$ learns $Q_{ij} = T_{ij} + X_{ij} \cdot \Delta_j$

Protocol `Correlated-OT-Extension`:

$\mathcal{R}$ has $K_{ij}^b$ from a prior setup phase, and $\mathcal{S}$
has $\Delta_i$ and $K_{ij}^{\Delta_i}$ from that setup phase.

$\mathcal{R}$ has an input matrix $X_{ij}$, with $i \in [\kappa]$, and $j \in [\lambda]$.

We also require a pseudo-random generator $\text{PRG} : \mathbb{F}_2^{\lambda} \to \mathbb{F}_2^{\kappa}$. 

1. $\mathcal{R}$ computes: $T_{ij}^b \gets \text{PRG}(K^b_{j \bullet})_i$.
2. $\mathcal{S}$ computes: $T_{ij}^{\Delta_j} \gets \text{PRG}(K^{\Delta_j}_{j \bullet})_i$.
3. $\mathcal{R}$ computes $U_{ij} = T_{ij}^0 + T_{ij}^1 + X_{ij}$.
4. $\star$ $\mathcal{R}$ sends $U_{ij}$ to $\mathcal{S}$
5. $\bullet$ $\mathcal{S}$ waits to receive $U_{ij}$.
6. $\mathcal{S}$ computes $Q_{ij} = \Delta_j \cdot U_{ij} + T_{ij}^{\Delta_j}$.
7. $\square$ $\mathcal{R}$ returns $T_{ij}^0$, and $\mathcal{S}$ returns $Q_{ij}$.

Note that since we're working in $\mathbb{F}_2$, we have $Q_{ij} = T_{ij}^0 + X_{ij} \cdot \Delta_j$.

## Random OT Extension

Random OT extension also uses $K^b_{ij}$, and $\Delta_i$ from the setup phase.
The output of this phase are $\kappa$ pairs of random field elements
$v_1^b, \ldots, v_\kappa^b$ in $\mathbb{F}_q$ for the sender, and $v_i^{b_i}$ for the receiver,
where $b_i$ is the receivers choice for the $i$-th element.

For the sake of this protocol, we can identifier vectors in $\mathbb{F}_2^\lambda$
with field elements in $\mathbb{F}_{2^\lambda}$, and we write $\text{mul}$ for
explicit multiplication in this field.

Protocol `Random-OT-Extension`:

$\mathcal{R}$ has $K^b_{ij}$ from a prior setup phase, and $\mathcal{S}$ has
$\Delta_i$ and $K_{ij}^{\Delta_i}$ from that same setup.

$\mathcal{R}$ has a vector of $\kappa$ bits $b_i$, they extend 
this to a vector of $\kappa' = \kappa + 2\lambda$ bits,
by padding with random bits.

1. $\mathcal{R}$ generates $s_{\mathcal{R}} \xleftarrow{R} \mathbb{F}_2^\lambda$,
and sets $\text{Com}_{\mathcal{R}} \gets H(s_{\mathcal{R}})$.
2. $\mathcal{S}$ generates $s_{\mathcal{S}} \xleftarrow{R} \mathbb{F}_2^\lambda$,
and sets $\text{Com}_{\mathcal{S}} \gets H(s_{\mathcal{S}})$.
3. $\star$ $\mathcal{R}$ sends $\text{Com}_{\mathcal{R}}$ to $\mathcal{S}$,
and $\mathcal{S}$ sends $\text{Com}_{\mathcal{S}}$ to $\mathcal{R}$.
4. $\bullet$ The parties wait to receive these values.
5. $\mathcal{R}$ sets $X_{ij} \gets b_ i 1_ j$. Where $1_j$ is a vector filled with $\lambda$ ones.
6. $\mathcal{R}$ and $\mathcal{S}$ run `Correlated-OT-Extension`, with batch size $\kappa'$, with $\mathcal{R}$
using $X_{ij}$ as its input.
The parties receive $T_{ij}$ and $Q_{ij}$ respectively.
7. $\star$ Each party $\mathcal{P}$ sends $s_{\mathcal{P}}$ to the other party.
8. $\bullet$ Each party waits to receive $s_{\mathcal{P}}$, and checks
that $\text{Com}_{\mathcal{P}} = H(s_\mathcal{P})$.
9. The parties set $s \gets s_{\mathcal{R}} + s_{\mathcal{S}}$, using a
PRG, the parties set $\chi_0, \ldots, \chi_\kappa' \gets \text{PRG}(s)$,
where $\chi_i \in \mathbb{F}_{2^\lambda}$.
10. $\mathcal{R}$ computes $x \gets \langle b_j, \chi_j\rangle$,
and $t \gets \langle \text{mul}(T_{i \bullet}, \chi_i), 1_i\rangle$.
11. $\star$ $\mathcal{R}$ sends $x$ and $t$ to $\mathcal{S}$.
12. $\mathcal{S}$ calculates $q \gets \langle \text{mul}(Q_{i\bullet}, \chi_i), 1_i \rangle$.
12. $\bullet$ $\mathcal{S}$ waits to receive $x$ and $t$, and checks that
$q = t + \text{mul}(x, \Delta)$.
13. $\mathcal{S}$ sets $v^0_i \gets H_i(Q_{i\bullet})$ and $v^1_i \gets H_i(Q_{i \bullet} + \Delta_\bullet)$, for $i \in [\kappa]$
14. $\mathcal{R}$ sets $v^{b_i}_i \gets H_i(T_{i\bullet})$, for $i \in [\kappa]$

# Multiplicative to Additive Conversion

# Multiplication

# Triple Generation

