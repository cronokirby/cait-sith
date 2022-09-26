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
\begin{align}
&\underline{\texttt{Gen}():}\cr
&\ x \xleftarrow{\$} \mathbb{F}_q\cr
&\ X \gets x \cdot G\cr
&\ \texttt{return } (x, X)\cr
\end{align}
$$

Next, signing:

$$
\begin{align}
&\underline{\texttt{Sign}(x : \mathbb{F}_q, m : \{0, 1\}^*):}\cr
&\ k \xleftarrow{\$} \mathbb{F}_q\cr
&\ K \gets \frac{1}{k} \cdot G\cr
&\ r \gets h(K)\cr
&\ \texttt{retry if } r = 0\cr
&\ s \gets k (\texttt{Hash}(m) + rx)\cr
&\ \texttt{return } (K, s)
\end{align}
$$

Note that we deviate slightly from ECDSA specifications by returning
the entire point $K$ instead of just $r$.
This makes it easier for downstream implementations to massage
the result signature into whatever format they need for compatability.

Finally, verification:

$$
\begin{align}
&\underline{\texttt{Verify}(X : \mathbb{G}, m : \{0, 1\}^*, (K, s) : \mathbb{G} \times \mathbb{F}_q):}\cr
&\ r \gets h(K)\cr
&\ \texttt{assert } r \neq 0, s \neq 0\cr
&\ \hat{K} \gets \frac{\texttt{Hash}(m)}{s} \cdot G + \frac{r}{s} \cdot X\cr
&\ \texttt{asssert } \hat{K} = K\cr
\end{align}
$$

# 3 Presigning

In the setup phase, the parties generated a $t$ threshold sharing
of the private key $x$, with the share of $\mathcal{P}_i$ being $x_i$.
The parties also hold the public key $X = x \cdot G$.

In the prior phase, a set of parties $\mathcal{P}_0$ of size $N_0$
came together to generate a $t_0 \geq t$ threshold sharing of triples $a^0$, $b^0$, $c^0 = a^0 b^0$
and $a^1$, $b^1$, $c^1 = a^1 b^1$ , along with values $A^\sigma = a^\sigma \cdot G$, $ B^\sigma = b^\sigma \cdot G$ and $C^\sigma = c^\sigma \cdot G$.

In the current phase, a set of parties $\mathcal{P}_1 \subseteq \mathcal{P}_0$
of size $N_1 \geq t_0$ wish to generate a threshold $t_1 \geq t$ sharing
of a pre-signature.

**Round 1:**

1. $T.\text{Add}(\mathcal{P}_0, t_0, \mathcal{P}_1, t_1, A^0, B^0, C^0, A^1, B^1, C^1)$
2. Each party $P_i$ linearizes their share of $x$, setting $x_i \gets \lambda(\mathcal{P}_1)_i \cdot x_i$.
3. Each party $P_i$ linearizes their triple shares, setting:

$$
(a_i^\sigma, b_i^\sigma, c_i^\sigma) \gets \lambda(\mathcal{P}_0)_i \cdot (a_i^\sigma, b_i^\sigma, c_i^\sigma)
$$

4. Each party $P_i$ generates $k\_i, d\_i \xleftarrow{\\$} \mathbb{F}_q$.
5. Each party $P_i$ sets $(K_i, D_i) \gets \psi(k_i, d_i)$ where:

$$
\psi(k_i, d_i) := (k_i \cdot G, d_i \cdot G)
$$


5. Each party $P_i$ sets $\text{Com}_i \gets H(K_i, D_I)$.
6. $\star$ Each party $P_i$ sends $\text{Com}_i$ to every other party.

**Round 2:**

1. Each $P_i$ waits to receive $\text{Com}_j$ from each other $P_j$.
2. Each $P_i$ sets $\text{Confirm}_i \gets H(\text{Com}_1, \ldots, \text{Com}_N)$.
3. $T.\text{Add}(\text{Confirm}_i)$
4. $\star$ Each $P_i$ sends $\text{Confirm}_i$ to every other party.
5. Each $P_i$ generates the proof $\pi_i \gets \text{Prove}(T, \text{Mau}(\psi, (K_i, D_i); k_i, d_i))$.
6. $\star$ Each $P_i$ sends $(K_i, D_i, \pi_i)$ to every other party.
7. Each $P_i$ sets:

$$
\begin{aligned}
\text{ka}\_i &\gets k_i + a\_i^0\cr
\text{db}\_i &\gets d_i + b\_i^0\cr
\text{xa}\_i &\gets x_i + a\_i^0\cr
\text{kb}\_i &\gets k_i + b\_i^0\cr
\end{aligned}
$$

8. $\star$ Each $P_i$ sends $(\text{ka}_i, \text{db}_i, \text{xa}_i, \text{kb}_i)$ to every other party.

9. Each $P_i$ generates $f_1, \ldots, f_{t_1 - 1} \xleftarrow{\$} \mathbb{F}_q$.
10. Each $P_i$ sets $f_0 \gets k_i$, and $\textbf{F}_i \gets \varphi(f_0, \ldots, f_{t_1 - 1})$ where:

$$
\varphi(f_0, \ldots, f_{t_1 - 1}) := \left[\left(\sum_i f_i \cdot j^i \right) \cdot G\ |\ j \in [0\ldots N]\right]
$$

(with the convention $0^0 = 1$).

11. Each $P_i$ generates a proof $\pi_i \gets \text{Prove}(T, \text{Mau}(\varphi, \textbf{F}_i; f_0, \ldots, f_{t_1 - 1}))$
12. $\star$ Each $P_i$ sends $(\textbf{F}_i, \pi_i)$ to every other party.
13. $\textcolor{red}{\star}$ Each $P_i$ *privately* sends $\text{k}_i^j := \sum_i f_i \cdot j^i$ to each other party $P_j$, and saves $\text{k}_i^i$ for itself.

**Round 3:**

1. Each $P_i$ waits to receive $\text{Confirm}_j$ from each other $P_j$.
2. $\blacktriangle$ Each $P_i$ *asserts* that $\forall j \in [N].\ \text{Confirm}_j = \text{Confirm}_i$, aborting otherwise.
3. Each $P_i$ waits to receive $(K_j, D_j, \pi_j)$ from each other $P_j$.
4. $\blacktriangle$ Each $P_i$ *asserts* that $\forall j \in [N].\ H(K_i, D_i) = \text{Com}_j \land \text{Verify}(T, \pi_j, \text{Mau}(\varphi, (K_i, D_i)))$.
5. Each $P_i$ waits to receive $(\text{ka}_j, \text{db}_j, \text{xa}_j, \text{kb}_j)$ from each other $P_j$.
6. Each $P_i$ sets:

$$
\begin{aligned}
K &\gets \sum_{i \in [N]} K_i \quad& D &\gets \sum_{i \in [N]} D_i\cr
\text{ka} &\gets \sum_{i \in [N]} \text{ka}_i \quad&
\text{db} &\gets \sum_{i \in [N]} \text{db}_i\cr
\text{xa} &\gets \sum_{i \in [N]} \text{xa}_i\quad&
\text{kb} &\gets \sum_{i \in [N]} \text{kb}_i\cr
\end{aligned}
$$

7. $\blacktriangle$ Each $P_i$ asserts that:

$$
\begin{aligned}
\text{ka} \cdot G &= K + A^0\cr
\text{db} \cdot G &= D + B^0\cr
\text{xa} \cdot G &= X + A^1\cr
\text{kb} \cdot G &= K + B^1\cr
\end{aligned}
$$

8. Each $P_i$ sets:

$$
\begin{aligned}
\text{kd}\_i &\gets \text{ka} \cdot d\_i - \text{db} \cdot a\_i^0 + c\_i^0\cr
g_0 &\gets \text{xa} \cdot k\_i - \text{kb} \cdot a\_i^1 + c\_i^1\cr
\end{aligned}
$$

9. $\star$ Each $P_i$ sends $\text{kd}_i$ to every other party.

10. Each $P_i$ generates $\g_1, \ldots, g_{t_1 - 1} \xleftarrow{\\$} \mathbb{F}_q$.
11. Each $P_i$ sets $\textbf{G}_i \gets \varphi(g_0, \ldots, g_n)$, where:

12. Each $P_i$ generates the proof $\pi_i \gets \text{Prove}(T, \text{Mau}(\varphi, \textbf{G}_i; \text{kx}^i\_0, \ldots, \text{kx}^i\_{t_1-1}))$.
13. $\star$ Each $P_i$ sends $(\textbf{G}_i, \pi_i)$ to every other party.
14. $\textcolor{red}{\star}$ Each $P_i$ *privately* sends $\text{kx}_i^j := \sum_i \alpha_i \cdot j^i$ to each other party $P_j$, and saves $\text{kx}_i^i$ for itself.
15. Each $P_i$ waits to receive $(\textbf{F}_j, \pi_j)$ from each other $P_j$.
16. $\blacktriangle$ Each $P_i$ *asserts* that $\forall j \in [N].\ \text{Verify}(T, \pi_j, \text{Mau}(\varphi, \textbf{F}_j))$.
17. Each $P_i$ sets $\textbf{F} \gets \sum_{j \in [N]} \textbf{F}_j$.
18. $\blacktriangle$ Each $P_i$ *asserts* that $\textbf{F}^0 = K$.
19. Each $P_i$ waits to receive $k_j^i$ from each other $P_j$.
20. Each $P_i$ sets $k\_i \gets \sum\_{j \in [N]} k\_j^i$
21. Each $P_i$ *asserts* that $\text{k}_i \cdot G = \textbf{F}^i$.
22. Each $P_i$ saves $k_i$.

**Round 4:**

1. Each $P_i$ waits to receive $\text{kd}_j$ from each other $P_j$.
2. Each $P_i$ sets $\text{kd} \gets \sum_{j \in [N]} \text{kd}_j$.
3. $\blacktriangle$ Each $P_i$ checks that $\text{kd} \cdot G = \text{ka} \cdot D - \text{db} \cdot A^0 + C^0$.
4. Each $P_i$ waits to receive $(\textbf{G}_j, \pi_j)$ from each other $P_j$.
5. $\blacktriangle$ Each $P_i$ *asserts* that $\forall j \in [N].\ \text{Verify}(T, \pi_j, \text{Mau}(\varphi, \textbf{G}_j))$.
6. Each $P_i$ sets $\textbf{G} \gets \sum_{j \in [N]} \textbf{G}_j$.
7. Each $P_i$ *asserts* that $\textbf{G}^0 = \text{xa} \cdot K - \text{kb} \cdot A^1 + C^1$.
8. Each $P_i$ waits to receive $\text{kx}_j^i$ from each other $P_j$.
9. Each $P_i$ sets $\text{kx}\_i \gets \sum\_{j \in [N]} \text{kx}\_j^i$
10. Each $P_i$ *asserts* that $\text{kx}_i \cdot G = \textbf{G}^i$.
11. Each $P_i$ modifies $K$, setting $K \gets \frac{1}{\text{kd}} \cdot K$, and then saves $K$.
12. Each $P_i$ sets $\sigma_i \gets h(K) \cdot \text{kx}_i$, then saves $\sigma_i$.

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

1. Each $P_i$ linearizes their share of $\sigma$, setting $\sigma_i \gets \lambda(\mathcal{P}_2)_i \cdot \sigma_i$.
2. Each $P_i$ sets $s_i \gets \text{Hash}(M)