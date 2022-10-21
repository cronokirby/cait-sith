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
&\ K \gets \frac{1}{k} \cdot G\cr
&\ r \gets h(K)\cr
&\ \texttt{retry if } r = 0\cr
&\ s \gets k (\texttt{Hash}(m) + rx)\cr
&\ \texttt{return } (K, s)
\end{aligned}
$$

Note that we deviate slightly from ECDSA specifications by returning
the entire point $K$ instead of just $r$.
This makes it easier for downstream implementations to massage
the result signature into whatever format they need for compatability.

Finally, verification:

$$
\begin{aligned}
&\underline{\texttt{Verify}(X : \mathbb{G}, m : \{0, 1\}^*, (K, s) : \mathbb{G} \times \mathbb{F}_q):}\cr
&\ r \gets h(K)\cr
&\ \texttt{assert } r \neq 0, s \neq 0\cr
&\ \hat{K} \gets \frac{\texttt{Hash}(m)}{s} \cdot G + \frac{r}{s} \cdot X\cr
&\ \texttt{asssert } \hat{K} = K\cr
\end{aligned}
$$

# 3 Presigning

In the setup phase, the parties generated a $t$ threshold sharing
of the private key $x$, with the share of $\mathcal{P}_i$ being $x_i$.
The parties also hold the public key $X = x \cdot G$.

In two prior phases $\sigma \in \\{0, 1\\}$, a set of parties $\mathcal{P}_0^\sigma$ of size $N_0^\sigma$
came together to generate a $t_0 \geq t$ threshold sharing of triples $a^\sigma$, $b^\sigma$, $c^\sigma = a^\sigma b^\sigma$
along with values $A^\sigma = a^\sigma \cdot G$, $B^\sigma = b^\sigma \cdot G$ and $C^\sigma = c^\sigma \cdot G$.

In the current phase, a set of parties $\mathcal{P}_ 1 \subseteq \mathcal{P}_ 0^0 \cap \mathcal{P}^1_ 0$
of size $N_1 \geq \text{max}(t_0^0, t_0^1)$ wish to generate a threshold $t_1 \geq t$ sharing
of a pre-signature.

**Round 1:**

1. Each $P_i$ checks that $\mathcal{P}_1 \subseteq \mathcal{P}_0^0 \cap \mathcal{P}_0^1$, that $t_1 \geq t$.
2. $T.\text{Add}(t, \mathcal{P}_0^0, t_0^0, \mathcal{P}_0^1, t_0^1, \mathcal{P}_1, t_1, A^0, B^0, C^0, A^1, B^1, C^1)$
3. Each party $P_i$ linearizes their share of $x$, setting $x_i \gets \lambda(\mathcal{P}_1)_i \cdot x_i$.
4. Each party $P_i$ linearizes their triple shares, setting:

$$
(a_i^\sigma, b_i^\sigma, c_i^\sigma) \gets \lambda(\mathcal{P}_1)_i \cdot (a_i^\sigma, b_i^\sigma, c_i^\sigma)
$$

5. Each $P_i$ samples $f \xleftarrow{\\\$} \mathbb{F}_ q[X]_ {\leq t - 1}$.
6. Each $P_i$ sets $F_ i \gets f \cdot G$.
7. Each $P_i$ generates $d_i \xleftarrow{\\\$} \mathbb{F}_q$, and sets $D_i \gets d_i \cdot G$.
8. Each party $P_i$ sets $\text{Com}_i \gets H(F_i, D_i)$.
9. $\star$ Each party $P_i$ sends $\text{Com}_i$ to every other party.

**Round 2:**

1. $\bullet$ Each $P_i$ waits to receive $\text{Com}_j$ from each other $P_j$.
2. Each $P_i$ sets $\text{Confirm}_i \gets H(\text{Com}_1, \ldots, \text{Com}_N)$.
3. $T.\text{Add}(\text{Confirm}_i)$
4. $\star$ Each $P_i$ sends $\text{Confirm}_i$ to every other party.
5. Each $P_i$ generates the proofs

$$
\begin{aligned}
\pi_i &\gets \text{Prove}(T.\text{Cloned}(\texttt{dlog0}, i), \text{Mau}(- \cdot G, F_ i(0); f(0)))\cr
\pi'_i &\gets \text{Prove}(T.\text{Cloned}(\texttt{dlog1}, i), \text{Mau}(- \cdot G, D_ i; d_ i))
\end{aligned}
$$

6. $\star$ Each $P_i$ sends $(F_i, \pi_i, D_i, \pi'_i)$ to every other party.
7. $\textcolor{red}{\star}$ Each $P_i$ *privately* sends $\text{k}_i^j := f(j)$ to each other party $P_j$, and saves $\text{k}_i^i$ for itself.
8. Each $P_i$ sets:

$$
\begin{aligned}
\text{ka}_ i &\gets f(0) + a^0_ i\cr
\text{db}_ i &\gets d_i + b^0_ i\cr
\text{xa}_ i &\gets x_i + a^1_ i\cr
\text{kb}_ i &\gets f(0) + b^1_ i\cr
\end{aligned}
$$

9. $\star$ Each $P_i$ sends $(\text{ka}_i, \text{db}_i, \text{xa}_i, \text{kb}_i)$ to every other party.

**Round 3:**

1. $\bullet$ Each $P_i$ waits to receive $\text{Confirm}_j$ from each other $P_j$.
2. $\blacktriangle$ Each $P_i$ *asserts* that $\forall P_j \in \mathcal{P}_1.\ \text{Confirm}_j = \text{Confirm}_i$, aborting otherwise.
3. $\bullet$ Each $P_i$ waits to receive $(F_j, \pi_j, D_j, \pi'_j)$ from each other $P_j$.
4. $\blacktriangle$ Each $P_i$ *asserts* that $\forall P_j \in \mathcal{P}_ 1$:

$$
\begin{aligned}
&\text{deg}(F_ j) = t - 1\cr
&H(F_ j, D_ j) = \text{Com}_ j\cr
&\text{Verify}(T.\text{Cloned}(\texttt{dlog0}, j), \pi_ j, \text{Mau}(- \cdot G, F_j(0)))\cr
&\text{Verify}(T.\text{Cloned}(\texttt{dlog1}, j), \pi_ j, \text{Mau}(- \cdot G, D_j))
\end{aligned}
$$

5. $\bullet$ Each $P_i$ waits to receive $k_j^i$ from each other party $P_j$.
6. Each $P_i$ sets $k_ i \gets \sum_{P_ j \in \mathcal{P}_ 1} k^i_ j$ and $K \gets \sum_ {P_ j \in \mathcal{P}_ 1} F_ j(0)$.
7. $\blacktriangle$ Each $P_i$ *asserts* that $k_i \cdot G = (\sum_{P_j \in \mathcal{P}_1} F_j)(i)$.
8. Each $P_i$ saves $k_i$ and $K$.
9. $\bullet$ Each $P_i$ waits to receive $(\text{ka}_j, \text{db}_j, \text{xa}_j, \text{kb}_j)$ from each other $P_j$.
10. Each $P_i$ sets:

$$
\begin{aligned}
D &\gets \sum_ {P_ j \in \mathcal{P}_ 1} D_ j\cr
\text{ka} &\gets \sum_ {P_ j \in \mathcal{P}_ 1} \text{ka}_ j \quad&
\text{db} &\gets \sum_ {P_ j \in \mathcal{P}_ 1} \text{db}_ j\cr
\text{xa} &\gets \sum_ {P_ j \in \mathcal{P}_ 1} \text{xa}_ j\quad&
\text{kb} &\gets \sum_ {P_ j \in \mathcal{P}_ 1} \text{kb}_ j\cr
\end{aligned}
$$

11. $\blacktriangle$ Each $P_i$ asserts that:

$$
\begin{aligned}
\text{ka} \cdot G &= K + A^0\cr
\text{db} \cdot G &= D + B^0\cr
\text{xa} \cdot G &= X + A^1\cr
\text{kb} \cdot G &= K + B^1\cr
\end{aligned}
$$

12. Each $P_i$ sets:

$$
\begin{aligned}
\text{kd}_ i &\gets \text{ka} \cdot d_ i - \text{db} \cdot a^0_ i + c^0_ i\cr
l_ 0 &\gets \text{xa} \cdot f(0) - \text{kb} \cdot a^1_ i + c^1_ i\cr
\end{aligned}
$$

13. $\star$ Each $P_i$ sends $\text{kd}_i$ to every other party.

14. Each $P_i$ generates $l_1, \ldots, l_ {t_1 - 1} \xleftarrow{\\\$} \mathbb{F}_q$, which, along with $l_0$, define a polynomial $l$
15. Each $P_i$ sets $L_ i \gets l \cdot G$.

16. Each $P_i$ generates the proof $\pi_i \gets \text{Prove}(T.\text{Cloned}(\texttt{dlog2}, i), \text{Mau}({- \cdot G}, L_i(0); l(0)))$.
17. $\star$ Each $P_i$ sends $(L_i, \pi_i)$ to every other party.
18. $\textcolor{red}{\star}$ Each $P_i$ *privately* sends $\text{kx}_i^j := l(j)$ to each other party $P_j$, and saves $\text{kx}_i^i$ for itself.

**Round 4:**

1. $\bullet$ Each $P_i$ waits to receive $\text{kd}_j$ from each other $P_j$.
2. Each $P_i$ sets $\text{kd} \gets \sum_{j \in [N]} \text{kd}_j$.
3. $\blacktriangle$ Each $P_i$ checks that $\text{kd} \cdot G = \text{ka} \cdot D - \text{db} \cdot A^0 + C^0$.
4. $\bullet$ Each $P_i$ waits to receive $(L_j, \pi_j)$ from each other $P_j$.
5. $\blacktriangle$ Each $P_i$ *asserts* that $\forall j \in [N].\ \text{deg}(L_j) = t - 1 \land \text{Verify}(T.\text{Cloned}(\texttt{dlog2}, j), \pi_j, \text{Mau}(- \cdot G, L_j(0)))$.
6. $\bullet$ Each $P_i$ waits to receive $\text{kx}_j^i$ from each other $P_j$.
7. Each $P_i$ sets $\text{kx}_ i \gets \sum_ {P_ j \in \mathcal{P}_ 1} \text{kx}^i_ j$ and $L \gets \sum_{P_j \in \mathcal{P}_1} L_j$.
8. $\blacktriangle$ Each $P_i$ *asserts* that $\text{kx}_ i \cdot G = L(i)$.
9. Each $P_i$ *asserts* that $L(0) = \text{xa} \cdot K - \text{kb} \cdot A^1 + C^1$.
10. Each $P_i$ modifies $K$, setting $K \gets \frac{1}{\text{kd}} \cdot D$, and then saves $K$.
11. Each $P_i$ sets $\sigma_i \gets h(K) \cdot \text{kx}_i$, then saves $\sigma_i$.

**Output**

The presignature consists of $(K, k, \sigma)$ with $k$ and $\sigma$ being
threshold shared as $k_1, \ldots, k_{N_1}$, and $\sigma_1, \ldots, \sigma_{N_1}$.

# 4 Signing

In the previous phase, a group of parties $\mathcal{P}_1$
generate a presignature $(K, k, \sigma)$, with the values
$k$, $\sigma$ being shared with a threshold of $t_1$.

In the signing phase, a group of parties $\mathcal{P}_2 \subseteq \mathcal{P}_1$ of size $\geq t_1$ consumes this presignature
to sign a message $m$.

**Round 1:**

1. Each $P_i$ linearizes their share of $k$, setting $k_i \gets \lambda(\mathcal{P}_2)_i \cdot k_i$.
2. Each $P_i$ linearizes their share of $\sigma$, setting $\sigma_i \gets \lambda(\mathcal{P}_2)_i \cdot \sigma_i$.
3. Each $P_i$ sets $s_i \gets \text{Hash}(M) \cdot k_i + \sigma_i$.
4. $\star$ Each $P_i$ sends $s_i$ to every other party.

**Round 2:**

1. $\bullet$ Each $P_i$ waits to receive $s_j$ from every other party.
2. Each $P_i$ sets $s \gets \sum_{j \in [N]} s_j$.
3. $\blacktriangle$ Each $P_i$ *asserts* that $(K, s)$ is a valid ECDSA signature for $m$.
4. Each $P_i$ outputs $(K, s)$.

**Output**

The pair $(K, s)$ is the signature.

