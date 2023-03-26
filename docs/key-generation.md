In this document, we describe a generalized version of key generation,
allowing for key refresh and resharing, and then apply that to
create two specific protocols:
1. A protocol for generating a fresh key.
2. A protocol for changing the threshold and set of participants but with the same key.


Given a set of players $\mathcal{P} = \{P_1, \ldots, P_N\}$,
and a desired threshold $t$, define
the following protocol:

## KeyShare

We assume that each participant in $\mathcal{P} := \\\{P_1, \ldots, P_n\\\}$
has a secret share $s_i$ (which can possibly be $0$), which sum to $s := \sum_i s_i$ and that they share a public value $S$,
which is either $\bot$ (meaning no value),
or should equal $s \cdot G$.

The goal of this protocol is for each particapant to obtain a fresh
threshold $t$ sharing of $s$, such that any $t$ participants
can reconstruct the value, along with the value $s \cdot G$,
if $S = \bot$.

**Round 1:**

1. $\blacktriangle$ Each $P_i$ *asserts* that $|\mathcal{P}| \geq t$.
2. $T.\text{Add}(\mathbb{G}, \mathcal{P}, t)$
3. Each $P_i$ samples $f \xleftarrow{\\\$} \mathbb{F}_ q[X]_ {\leq t - 1}$,
subject to the constraint that $f(0) = s_i$.
4. Each $P_i$ sets $F_ i \gets f \cdot G$.
5. Each $P_i$ sets $(\text{Com}_i, r_i) \gets \text{Commit}(F_i)$.
6. $\star$ Each $P_i$ sends $\text{Com}_i$ to every other party.

**Round 2:**

1. $\bullet$ Each $P_i$ waits to receive $\text{Com}_j$ from each other $P_j$.
2. Each $P_i$ sets $\text{Confirm}_i \gets H(\text{Com}_1, \ldots, \text{Com}_N)$.
3. $T.\text{Add}(\text{Confirm}_i)$
4. $\star$ Each $P_i$ sends $\text{Confirm}_i$ to every other party.
5. Each $P_i$ generates the proof $\pi_i \gets \text{Prove}(T.\text{Cloned}(\texttt{dlog0}, i), \text{Mau}(- \cdot G, F_{i}(0); f(0)))$.
6. $\star$ Each $P_i$ sends $(F_i, r_i, \pi_i)$ to every other party.
7. $\textcolor{red}{\star}$ Each $P_i$ *privately* sends $x_i^j := f(j)$ to each other party $P_j$, and saves $x_i^i$ for itself.

**Round 3:**

1. $\bullet$ Each $P_i$ waits to receive $\text{Confirm}_j$ from each other $P_j$.
2. $\blacktriangle$ Each $P_i$ *asserts* that $\forall j \in [N].\ \text{Confirm}_j = \text{Confirm}_i$, aborting otherwise.
3. $\bullet$ Each $P_i$ waits to receive $(F_j, r_j, \pi_j)$ from each other $P_j$.
4. $\blacktriangle$ Each $P_i$ *asserts* that $\forall j \in [N].\ \text{deg}(F_ j) = t -1 \land \text{CheckCommit}(\text{Com}_j, F_j, r_j) \land \text{Verify}(T.\text{Cloned}(\texttt{dlog0}, j), \pi_j, \text{Mau}({- \cdot G}, F_j(0)))$.
5. $\bullet$ Each $P_i$ waits to receive $x_j^i$ from each other $P_j$.
6. Each $P_i$ sets $x_i \gets \sum_j x^i_j$ and $X \gets \sum_j F_j(0)$.
7. $\blacktriangle$ Each $P_i$ asserts that $x_i \cdot G = (\sum_j F_j)(i)$.
8. (If $S \neq \bot$) $\blacktriangle$ Each $P_i$ asserts that $X = S$.
9. Each $P_i$ outputs $x_i$ and $X$.

**Output**

The value $x_i$ is $P_i$'s private share of the secret key $s$.

$X$ is the public key shared by the group, which should be equal
to the previous value $S$, if it was provided.

## Key Generation

The key sharing protocol can be used for a standard key generation
protocol, by having each party sample $s_i$ randomly,
and setting $S = \bot$ (no expected public key).

## Key Refresh

A key refresh protocol can be performed by first linearizing the
shares $x_1, \ldots, x_n$,
setting $s_i \gets \lambda(\mathcal{P})_i \cdot x_i$,
and then using $S = X$, to check that the public key doesn't
change.

## Key Resharing

A key resharing protocol can be performed as well.
This involves transitioning from $(\mathcal{P}, t)$
to $(\mathcal{P}', t')$, and can be performed as long
as $|\mathcal{P} \cap \mathcal{P}'| \geq t$,
i.e. there are enough old parties with a share.
The end result is that the new set of parties
hold threshold $t'$ shares of the same private key.

This works by having each party in $\mathcal{P} \cap \mathcal{P}'$ linearize their share,
setting $s_i \gets \lambda(\mathcal{P})_i \cdot x_i$.
Each party in $\mathcal{P}' / \mathcal{P}$ (the new members),
simply set $s_i \gets 0$.
We also set $S = X$, to check that the same public key
is generated.

Key refresh can be seen as a natural case of
key resharing, with $\mathcal{P} = \mathcal{P}'$,
and $t = t'$.
