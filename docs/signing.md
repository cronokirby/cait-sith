This document specifies the signing protocol.
The protocol is split into two main phases, a pre-signing phase

# 1 Preliminaries

Let $\mathbb{G}$ be a cryptographic group, with generator $G$, of prime order $q$.

Let $\text{Hash} : \\{0, 1\\}^* \to \mathbb{F}_q$ denote a hash function used for hashing messages
for signatures.
Let $h : \mathbb{G} \to \mathbb{F}_q$ denote a different "hash function" used for converting points to scalars.
Commonly, this is done by "simply" taking the x coordinate of the affine
representation of a point.
Let $H : \\{0, 1\\}^* \to \\{0, 1\\}^{2\lambda}$ be a generic hash function.

# 2 ECDSA Recap

ECDSA is defined by algorithms for key generation, signing, and verification:

First, key generation:

$$
\begin{aligned}
&\underline{\texttt{Gen}():}\cr
&\ x \xleftarrow{\$} \mathbb{F}_q\cr
&\ X \gets x \cdot G\cr
&\ \texttt{return } (x, X)\cr
\end{aligned}
$$

Next, signing:

$$
\begin{aligned}
&\underline{\texttt{Sign}(x : \mathbb{F}_q, m : \{0, 1\}^*):}\cr
&\ k \xleftarrow{\$} \mathbb{F}_q\cr
&\ R \gets \frac{1}{k} \cdot G\cr
&\ r \gets h(R)\cr
&\ \texttt{retry if } r = 0\cr
&\ s \gets k (\texttt{Hash}(m) + rx)\cr
&\ \texttt{return } (R, s)
\end{aligned}
$$

Note that we deviate slightly from ECDSA specifications by returning
the entire point $R$ instead of just $r$.
This makes it easier for downstream implementations to massage
the result signature into whatever format they need for compatability.

Finally, verification:

$$
\begin{aligned}
&\underline{\texttt{Verify}(X : \mathbb{G}, m : \{0, 1\}^*, (R, s) : \mathbb{G} \times \mathbb{F}_q):}\cr
&\ r \gets h(R)\cr
&\ \texttt{assert } r \neq 0, s \neq 0\cr
&\ \hat{R} \gets \frac{\texttt{Hash}(m)}{s} \cdot G + \frac{r}{s} \cdot X\cr
&\ \texttt{asssert } \hat{R} = R\cr
\end{aligned}
$$

# 3 Presigning

In the setup phase, the parties generated a $t$ threshold sharing
of the private key $x$, with the share of $\mathcal{P}_i$ being $x_i$.
The parties also hold the public key $X = x \cdot G$.

In two prior phases $\sigma \in \\{0, 1\\}$, a set of parties $\mathcal{P}_0^\sigma$ of size $N_0^\sigma$
came together to generate a $t$ threshold sharing of triples $a^\sigma$, $b^\sigma$, $c^\sigma = a^\sigma b^\sigma$
along with values $A^\sigma = a^\sigma \cdot G$, $B^\sigma = b^\sigma \cdot G$ and $C^\sigma = c^\sigma \cdot G$.

In the current phase, a set of parties $\mathcal{P}_ 1 \subseteq \mathcal{P}_ 0^0 \cap \mathcal{P}^1_ 0$
of size $N_1 \geq t$ wish to generate a threshold $t' = t$ sharing
of a pre-signature.

**Round 1:**

1. Each $P_i$ checks that $\mathcal{P}_1 \subseteq \mathcal{P}_0^0 \cap \mathcal{P}_0^1$, and that $t' = t$.
2. Each $P_i$ renames:

$$
\begin{aligned}
&k_i \gets a^0_i, &d_i \gets b^0_i,\quad &\text{kd}_i \gets c^0_i\cr
&K \gets A^0, &D \gets B^0,\quad &\text{KD} \gets C^0\cr
&a \gets a^1_i, &b \gets b^1_i,\quad &c \gets c^1_i\cr
&A \gets A^1, &B \gets B^1,\quad &C \gets C^1\cr
\end{aligned}
$$

3. Then, each $P_i$ linearizes their shares, setting:

$$
\begin{aligned}
(k'_i, d_i, \text{kd}_i) &\gets \lambda(\mathcal{P}_1)_i \cdot (k_i, d_i, \text{kd}_i)\cr
(a'_i, b'_i, c'_i) &\gets \lambda(\mathcal{P}_1)_i \cdot (a_i, b_i, c_i)\cr
x'_i &\gets \lambda(\mathcal{P}_1)_i \cdot x_i\cr
\end{aligned}
$$

4. $\star$ Each $P_i$ sends $\text{kd}_i$ to every other party.
5. Each $P_i$ sets:

$$
\begin{aligned}
&\text{ka}_i \gets k'_i + a'_i\cr
&\text{xb}_i \gets x'_i + b'_i\cr
\end{aligned}
$$

6. $\star$ Each $P_i$ sends $\text{ka}_i$ and $\text{xb}_i$ to every other party.

**Round 2:**

1. $\bullet$ Each $P_i$ waits to receive $\text{kd}_j$ from each other $P_j$.
2. Each $P_i$ sets $\text{kd} \gets \sum_j \text{kd}_j$.
3. $\blacktriangle$ Each $P_i$ *asserts* that $\text{kd} \cdot G = \text{KD}$.
4. $\bullet$ Each $P_i$ waits to receive $\text{ka}_j$ and $\text{xb}_j$ from from every other party $P_j$.
5. Each $P_i$ sets $\text{ka} \gets \sum_j \text{ka}_j$ and $\text{xb} \gets \sum_j \text{xb}_j$.
6. $\blacktriangle$ Each $P_i$ asserts that:

$$
\begin{aligned}
\text{ka} \cdot G &= K + A\cr
\text{xb} \cdot G &= X + B
\end{aligned}
$$

7. Each $P_i$ sets: $R \gets \frac{1}{\text{kd}} \cdot D$.
8. Each $P_i$ sets $\sigma_i \gets \text{ka} \cdot x_i - \text{xb} \cdot a_i + c_i$, which is already threshold shared.

**Output:**
The output is the presignature $(R, k, \sigma)$, with $k$ and $\sigma$
threshold shared as $k_1, \ldots$ and $\sigma_1, \ldots$.

# 4 Signing

In the previous phase, a group of parties $\mathcal{P}_1$
generate a presignature $(R, k, \sigma)$, with the values
$k$, $\sigma$ being shared with a threshold of $t$.

In the signing phase, a group of parties $\mathcal{P}_2 \subseteq \mathcal{P}_1$ of size $\geq t$ consumes this presignature
to sign a message $m$.

**Round 1:**

1. Each $P_i$ linearizes their share of $k$, setting $k_i \gets \lambda(\mathcal{P}_2)_i \cdot k_i$.
2. Each $P_i$ linearizes their share of $\sigma$, setting $\sigma_i \gets \lambda(\mathcal{P}_2)_i \cdot \sigma_i$.
3. Each $P_i$ sets $s_i \gets \text{Hash}(M) \cdot k_i + h(R) \sigma_i$.
4. $\star$ Each $P_i$ sends $s_i$ to every other party.

**Round 2:**

1. $\bullet$ Each $P_i$ waits to receive $s_j$ from every other party.
2. Each $P_i$ sets $s \gets \sum_{j \in [N]} s_j$.
3. $\blacktriangle$ Each $P_i$ *asserts* that $(R, s)$ is a valid ECDSA signature for $m$.
4. Each $P_i$ outputs $(R, s)$.

**Output**

The pair $(R, s)$ is the signature.

