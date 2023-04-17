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

The goal of the setup phase is for each unordered pair of parties $P_a$
and $P_b$ to run a $\lambda$ batched random OT.
Each pair will be run only once, so we need to agree on a canonical
way to determine which of two parties $P_a$ and $P_b$
will act as the sender.
We do this by imposing a total order $<$ on the parties, and $P_a$
is the sender in the $(P_a, P_b)$ pair, if $P_a < P_b$.

The end result is that $P_a$ will learn $K_{ij}^0$ and $K_{ij}^1$,
and $P_b$ will learn $K_{ij}^{\Delta_ i}$, for a randomly chosen $\Delta \in \mathbb{F}_2^{\lambda}$.

In more detail:

Protocol `Triples-Setup`

In parallel, for each unordered pair of parties $P_a$ and $P_b$
$P_b$ samples $\Delta \xleftarrow{R} \mathbb{F}_2^\lambda$,
and then $P_a$ and $P_b$ run `Batch-Random-OT` with a batch size
of $\lambda$, and save the result.
Note that communication in this subprotocol should be *private*.

# Extended Oblivious Transfer

The goal of the extended oblivious transfer protocol is for two parties
to extend their joint setup, and use that setup to generate $\kappa$ oblivious
transfers, using fast symmetric key primitives.

We use the [KOS15](https://eprint.iacr.org/2015/546),
specifically, the amended version using SoftspokenOT.

## Correlated OT Extension

We start with the *correlated* extension protocol.

The correlation comes from the $\Delta$ value used in the setup, controlled
by the sender $\mathcal{S}$.
Note that the sender was the receiver in the original setup.
In this protocol $\mathcal{R}$ uses an input matrix $X_{ij}$, and learns a random boolean matrix
$T_{ij} \in \mathbb{F}_ 2$, $i \in [\kappa], j \in [\lambda]$,
and $\mathcal{S}$ learns $Q_{ij} = T_{ij} + X_{ij} \cdot \Delta_ j$

Protocol `Correlated-OT-Extension`:

$\mathcal{R}$ has $K_{ij}^b$ from a prior setup phase, and $\mathcal{S}$
has $\Delta_i$ and $K_{ij}^{\Delta_i}$ from that setup phase.

$\mathcal{R}$ has an input matrix $X_{ij}$, with $i \in [\kappa]$, and $j \in [\lambda]$.

We also require a pseudo-random generator $\text{PRG} : \mathbb{F}_2^{\lambda} \to \mathbb{F}_2^{\kappa}$. 
This generator is parameterized by a session id $\text{sid}$, allowing the same
setup to be used for multiple extensions, so long as $\text{sid}$ is **unique**
for each execution.

1. $\mathcal{R}$ computes: $T_ {ij}^b \gets \text{PRG}_ {\text{sid}}(K^b_ {j \bullet})_ i$.
2. $\mathcal{S}$ computes: $T_ {ij}^{\Delta_ j} \gets \text{PRG}_ {\text{sid}}(K^{\Delta_ j}_ {j \bullet})_ i$.
3. $\mathcal{R}$ computes $U_{ij} = T_{ij}^0 + T_{ij}^1 + X_{ij}$.
4. $\star$ $\mathcal{R}$ sends $U_{ij}$ to $\mathcal{S}$
5. $\bullet$ $\mathcal{S}$ waits to receive $U_{ij}$.
6. $\mathcal{S}$ computes $Q_{ij} = \Delta_j \cdot U_{ij} + T_{ij}^{\Delta_j}$.
7. $\square$ $\mathcal{R}$ returns $T_{ij}^0$, and $\mathcal{S}$ returns $Q_{ij}$.

Note that since we're working in $\mathbb{F}_ 2$, we have $Q_ {ij} = T_ {ij}^0 + X_ {ij} \cdot \Delta_ j$.

## Random OT Extension

Random OT extension also uses $K^b_{ij}$, and $\Delta_i$ from the setup phase.
The output of this phase are $\kappa$ pairs of random field elements
$v_1^b, \ldots, v_\kappa^b$ in $\mathbb{F}_q$ for the sender, and $v_i^{b_i}$ for the receiver,
where $b_i$ is random bit for the $i$-th element.

For the sake of this protocol, we can identifier vectors in $\mathbb{F}_ 2^\lambda$
with field elements in $\mathbb{F}_ {2^\lambda}$, and we write $\text{mul}$ for
explicit multiplication in this field.

Protocol `Random-OT-Extension`:

$\mathcal{R}$ has $K^b_{ij}$ from a prior setup phase, and $\mathcal{S}$ has
$\Delta_i$ and $K_{ij}^{\Delta_i}$ from that same setup.

This protocol is also parameterized by a unique session id $\text{sid}$

1. $\mathcal{R}$ generates a random vector $b_ i \in \mathbb{F}_ 2$, with $i \in [\kappa']$, and sets $X_ {ij} \gets b_ i 1_ j$. Where $1_ j$ is a vector filled with $\lambda$ ones.
2. $\mathcal{R}$ and $\mathcal{S}$ run `Correlated-OT-Extension`, with batch size $\kappa'$, and session id $\text{sid}$ with $\mathcal{R}$
using $X_{ij}$ as its input.
The parties receive $T_ {ij}$ and $Q_ {ij}$ respectively.
3. $\mathcal{S}$ samples $s \xleftarrow{R} \mathbb{F}_2^\lambda$.
4. $\star$ $\mathcal{S}$ sends $s$ to $\mathcal{R}$.
5. $\bullet$ $\mathcal{R}$ waits to receive $s$.
6. Let $\mu \gets \lceil \kappa' / \lambda \rceil$,
then, the parties set $\hat{T}_ {ij}$, $\hat{b}_ i$, $\hat{Q}_ {ij}$,
with $i \in [\mu]$, $j \in [\lambda]$ by grouping adjacent bits
into elements of the field $\mathbb{F}_ {2^\lambda}$.

7. The parties use a
PRG to set $\chi_1, \ldots, \chi_\mu \gets \text{PRG}(s)$,
where $\chi_i \in \mathbb{F}_{2^\lambda}$.
8. $\mathcal{R}$ computes $x \gets \langle \hat{b}_ i, \chi_ i \rangle$,
and $t_ j \gets \langle \text{mul}(\hat{T}_ {i j}, \chi_i), 1_ i\rangle$.
9. $\star$ $\mathcal{R}$ sends $x$ and $t_ 1, \ldots, t_ {\lambda}$ to $\mathcal{S}$.
10. $\mathcal{S}$ calculates $q_j \gets \langle \text{mul}(\hat{Q}_{ij}, \chi_i), 1_i \rangle$.
11. $\bullet$ $\mathcal{S}$ waits to receive $x$ and $t_j$, and checks that
$q_j = t_j + \Delta_j \cdot x$.
12. $\mathcal{S}$ sets $v^0_i \gets H_i(Q_{i\bullet})$ and $v^1_i \gets H_i(Q_{i \bullet} + \Delta_\bullet)$, for $i \in [\kappa]$
13. $\mathcal{R}$ sets $v^{b_ i}_ i \gets H_ i(T_ {i\bullet})$, for $i \in [\kappa]$

# Multiplicative to Additive Conversion

We follow [HMRT21](https://eprint.iacr.org/2021/1373).

In this protocol, two parties $\mathcal{S}$ and $\mathcal{R}$ have values
$a, b \in \mathbb{F}_q$ respectively.
The output of this protocol has each party receiver $\alpha, \beta \in \mathbb{F}_q$
respectively, such that $\alpha + \beta = a \cdot b$.

This protocol requires the parties to have a triple setup.
Additionally, rather than describing the protocol as making a call to a random
OT extension internally, we instead say that the participants must have done
this prior to the protocol.
This makes our description of using a single OT extension for multiple instances
of MTA easier.

Protocol `MTA`:

Let $\kappa = \lceil \lg q \rceil + \lambda$.

The parties have, in a previous phase, have generated correlated randomness
of the following form:

$$
\begin{aligned}
&v_i^0, v_i^1 \xleftarrow{R} \mathbb{F}_q\ (i \in [\kappa])\cr
&t_i \xleftarrow{R} \mathbb{F}_2\cr
&\mathcal{S} \texttt{ receives } (v_i^0, v_i^1)\cr
&\mathcal{R} \texttt{ receives } (t_i, v_i^{t_i})\cr
\end{aligned}
$$

1. $\mathcal{S}$ samples random $\delta_1, \ldots, \delta_\kappa \xleftarrow{R} \mathbb{F}_q$.
2. $\star$ $\mathcal{S}$ sends $(-a + \delta_i + v_i^0, a + \delta_i + v_i^1)$ to $\mathcal{R}$.
3. $\bullet$ $\mathcal{R}$ waits to receive $(c^0_i, c^1_i)$ from $\mathcal{S}$, and
sets $m_i \gets c^{t_i}_i - v_i^{t_i}$
4. $\mathcal{R}$ samples $s \xleftarrow{R} \mathbb{F}_2^\lambda$, and
extends this into $\chi_2, \ldots, \chi_\kappa \gets \text{PRG}(s)$.
$\mathcal{S}$ then sets $\chi_ 1 \gets (-1)^{t_ 1}(b - \sum_{i \in [2\ldots \kappa]} \chi_ i \cdot (-1)^{t_ i})$.
(This makes it so that $b = \langle \chi_ i,  (-1)^{t_ i} \rangle$)
5. $\mathcal{R}$ saves $\beta = \langle \chi_ i, m_ i \rangle$.
6. $\star$ $\mathcal{R}$ sends $s$ and $\chi_ 1$ to $\mathcal{S}$.
7. $\bullet$ $\mathcal{S}$ waits to receive $s$ and $\chi_ 1$, and uses $s$
to expand $\chi_ 2, \ldots, \chi_\kappa \gets \text{PRG(s)}$.
8. $\square$ $\mathcal{S}$ outputs  $\alpha \gets - \langle \chi_ i, \delta_ i \rangle$

In the presence of malicious parties, this protocol may return a result
such that $\alpha + \beta$ is *not* $ab$, however, malicious parties
cannot learn information about the other party's result, except with
negligible probability.

Our triple generation protocol will take care of multiplication potentially
being wrong.

# Multiplication

This protocol involves $n$ parties $P_1, \ldots, P_n$.
Each of them has a share $a_i$ and $b_i$, of global values $a$ and $b$ in $\mathbb{F}_q$.

The goal is for each party to obtain a share $c_i$ of $c = ab$.

The idea behind the protocol is to use the decomposition:

$$
c = ab = (\sum_i a_i)(\sum_j b_j) = \sum_{ij} a_i b_j
$$

We run the `MTA` protocol for each unordered pair of parties, giving each party
two shares $\gamma^0_i$, and $\gamma^1_i$, which they then add to $a_{i} b_i$ to
get their share $c_i$.

The protocol is also parameterized by a unique session id $\text{sid}$,
and requires the triple setup phase to have been performed.

Protocol `Multiplication`:

In parallel, for each order pair of parties $P_i < P_j$,
with $\mathcal{S} = P_i$, being the sender, and $\mathcal{R} = P_j$
being the receiver.

Let $\kappa = \lceil q \rceil + \lambda$.

1. $\mathcal{S}$ and $\mathcal{R}$ run `Random-OT-Extension` with $\text{sid}$ and a batch size of $2 \kappa$.
$\mathcal{S}$ receives $v_i^0, v_i^1$, and $\mathcal{R}$ receives $t_i$ and $v_i^{t_i}$.

In parallel, for $(a,b) = (a_i, b_j)$  and $(a, b) = (b_i, a_j)$:

2. $\mathcal{S}$ and $\mathcal{R}$ run `MTA` using the first (or last, in the second
instance) $\kappa$ elements of the previous step, as well as their respective inputs
$a$ and $b$.

3. $\mathcal{S}$ receives $\gamma_j^0, \gamma_j^1$, and $\mathcal{R}$ receives
$\gamma_i^0, \gamma_i^1$. (Writing it this way means that each party has 
one instance of $\gamma$ for every other party they're interacting with).

After all the p2p interactions are done:

4. Every party $P_i$ sets $c_i = a_i b_i + \sum_j (\gamma_j^0 + \gamma_j^1)$.

# Triple Generation

The goal of triple generation is to generate *threshold* shares
of values $a, b, c$ such that $ab = c$.
Additionally, the parties should also learn $A = a \cdot G$, $B = b \cdot G$,
and $C = c \cdot G$.

More concretely, we have a set of parties $\mathcal{P}$ of size $N$,
which want to generate a triple with threshold $t$.

**Round 1:**

1. $T.\text{Add}(\mathbb{G}, \mathcal{P}, t)$
2. Each $P_ i$ samples $e, f, l \xleftarrow{R} \mathbb{F}_ q[X]_ {\leq (t - 1)}$.
3. Each $P_ i$ sets $l(0) = 0$.
3. Each $P_i$ sets $E_i \gets e \cdot G, F_i \gets f \cdot G, L_i \gets l \cdot G$.
4. Each $P_i$ sets $(\text{Com}_i, r_i) \gets \text{Commit}((E_i, F_i, L_i))$.
5. $\star$ Each $P_i$ sends $\text{Com}_i$ to all other parties.

**Round 2:**

1. $\bullet$ Each $P_i$ waits to receive $\text{Com}_j$ from each other $P_j$.
2. Each $P_i$ sets $\text{Confirm}_i \gets H(\text{Com}_1, \ldots, \text{Com}_N)$.
3. $T.\text{Add}(\text{Confirm}_i)$
4. In *parallel* to the following steps, the parties run `Multiplication` using
$\text{Confirm}_i$ as the session id, and using $e(0)$ and $f(0)$ as their personal shares.
5. $\star$ Each $P_i$ sends $\text{Confirm}_i$ to every other party.
6. Each $P_i$ generates the proofs:

$$
\begin{aligned}
\pi^0_i &\gets \text{Prove}(T.\text{Cloned}(\texttt{dlog0}, i), \text{Mau}(- \cdot G, E_i(0); e(0)))\cr
\pi^1_i &\gets \text{Prove}(T.\text{Cloned}(\texttt{dlog1}, i), \text{Mau}(- \cdot G, F_i(0); f(0)))\cr
\end{aligned}
$$

7. $\star$ Each $P_i$ sends $(E_i, F_i, L_i, r_i, \pi^0_i, \pi^1_i)$ to every other party.
7. $\textcolor{red}{\star}$ Each $P_i$ *privately* sends $a_i^j = e(j)$ and $b_i^j$ = $f(j)$ to every other party $P_j$.

**Round 3:**

1. $\bullet$ Each $P_i$ waits to receive $\text{Confirm}_j$ from each other $P_j$.
2. $\blacktriangle$ Each $P_i$ *asserts* that $\forall P_j.\ \text{Confirm}_j = \text{Confirm}_i$.
3. $\bullet$ Each $P_i$ waits to receive $(E_j, F_j, L_j, r_i, \pi^0_j, \pi^1_j)$ from each other $P_j$.
4. $\blacktriangle$ Each $P_i$ asserts that $\forall P_j$:

$$
\begin{aligned}
&\text{deg}(E_j) = \text{deg}(F_j) = \text{deg}(L_j) = t - 1\cr
&\forall j. L_j(0) = 0\cr
&\text{CheckCommit}(\text{Com}_j, (E_j, F_j, L_j), r_j)\cr
&\text{Verify}(T.\text{Cloned}(\texttt{dlog0}, j), \pi^0_j, \text{Mau}(- \cdot G, E_j(0)))\cr
&\text{Verify}(T.\text{Cloned}(\texttt{dlog1}, j), \pi^1_j, \text{Mau}(- \cdot G, F_j(0)))\cr
\end{aligned}
$$

5. $\bullet$ Each $P_i$ waits to receive $a^i_j$ and $b^i_j$ from every other $P_j$.
6. Each $P_i$ sets $a_i \gets \sum_j a^i_j$, $b_i \gets \sum_j b^i_j$, $E \gets \sum_j E_j$, and $F \gets \sum_j F_j$.
7. $\blacktriangle$ Each $P_i$ *asserts* that $E(i) = a_i \cdot G$ and $F(i) = b_i \cdot G$.
8. Each $P_i$ sets $C_i \gets e(0) \cdot F(0)$.
9. Each $P_I$ generates the proof:

$$
\pi_i \gets \text{Prove}(T.\text{Cloned}(\texttt{dlogeq0}, i), \text{Mau}((- \cdot G, - \cdot F(0)), (E_i(0), C_i); e(0))
$$

10. $\star$ Each $P_i$ sends $(C_i, \pi_i)$ to every other party.

**Round 4:**

1. $\bullet$ Each $P_i$ waits to receive $(C_j, \pi_j)$ from each other $P_j$.
2. $\blacktriangle$ Each $P_i$ *asserts* that $\forall P_j$:

$$
\text{Verify}(T.\text{Cloned}(\texttt{dlogeq0}, j), \pi_j, \text{Mau}((- \cdot G, - \cdot F(0)), (E_j(0), C_j)))
$$

3. Each $P_i$ sets $C \gets \sum_i C_i$.
4. $\bullet$ Each $P_i$ waits to receive $l_0$ from the `Multiplication` protocol.
5. Each $P_i$ sets $\hat{C}_i = l_0 \cdot G$.
6. Each $P_i$ generates the proof:

$$
\begin{aligned}
\pi_i &\gets \text{Prove}(T.\text{Cloned}(\texttt{dlog2}, i), \text{Mau}(- \cdot G, \hat{C}_i; l_0)))\cr
\end{aligned}
$$

7. $\star$ Each $P_i$ sends $(\hat{C}_i, \pi_i)$ to every other party.
8. $\textcolor{red}{\star}$ Each $P_i$ *privately* sends $c_i^j \gets l_0 + l_i(j)$ to every other $P_j$.

**Round 5:**

1. $\bullet$ Each $P_i$ waits to receive $(\hat{C}_j, \pi_j)$ from every other party.
2. $\blacktriangle$ Each $P_i$ *asserts* that (for all $j$):

$$
\begin{aligned}
&\text{Verify}(T.\text{Cloned}(\texttt{dlog2}, j), \pi_j, \text{Mau}(- \cdot G, \hat{C}_j)\cr
\end{aligned}
$$

3. Each $P_i$ sets $L \gets \sum_i \hat{C}_i + L_i$.
4. $\blacktriangle$ Each $P_i$ *asserts* that $C = L(0)$.
5. $\bullet$ Each $P_i$ waits to receive $c_j^i$ from every other $P_j$.
6. Each $P_i$ sets $c_i \gets \sum_j c_j^i$.
7. $\blacktriangle$ Each $P_i$ *asserts* that $L(i) = c_i \cdot G$.
8. Each $P_i$ sets $A \gets E(0)$, $B \gets F(0)$.
9. $\square$ Each $P_i$ returns $((a_i, b_i, c_i), (A, B, C))$.

