Given a set of players $\mathcal{P} = \{P_1, \ldots, P_N\}$,
and a desired threshold $t$, define
the following protocol:

### KeyGen


**Round 1:**

1. $T.\text{Add}(\mathcal{P}, t)$
2. Each $P_i$ generates $a_0, \ldots, a_{t - 1} \xleftarrow{R} \mathbb{F}_q$.
3. Each $P_i$ sets $\textbf{F}\_i \gets \varphi(a\_0, \ldots, a\_{t-1})$ where:

$$
\varphi(a_0, \ldots, a_{t - 1}) := \left[\left(\sum_i a_i \cdot j^i\right) \cdot G \ |\ j \in [N] \right]
$$

4. Each $P_i$ sets $\text{Com}_i \gets H(\textbf{F}_i)$.
5. $\star$ Each $P_i$ sends $\text{Com}_i$ to every other party.

**Round 2:**

1. Each $P_i$ waits to receive $\text{Com}_j$ from each other $P_j$.
2. Each $P_i$ sets $\text{Confirm}_i \gets H(\text{Com}_1, \ldots, \text{Com}_N)$.
3. $T.\text{Add}(\text{Confirm}_i)$
4. $\star$ Each $P_i$ sends $\text{Confirm}_i$ to every other party.
5. Each $P_i$ generates the proof $\pi_i \gets \text{Prove}(T, \text{Mau}(\varphi, \textbf{F}_i; a\_0, \ldots, a\_{t-1}))$
6. $\star$ Each $P_i$ sends $(\textbf{F}_i, \pi_i)$ to every other party.
7. $\textcolor{red}{\star}$ Each $P_i$ *privately* sends $x_i^j := \sum_i a_i \cdot j^i$ to each other party $P_j$, and saves $x_i^i$ for itself.

**Round 3:**

1. Each $P_i$ waits to receive $\text{Confirm}_j$ from each other $P_j$.
2. $\blacktriangle$ Each $P_i$ *asserts* that $\forall j \in [N].\ \text{Confirm}_j = \text{Confirm}_i$, aborting otherwise.
3. Each $P_i$ waits to receive $(\textbf{F}_j, \pi_j)$ from each other $P_j$.
4. $\blacktriangle$ Each $P_i$ *asserts* that $\forall j \in [N].\ H(\textbf{F}_j) = \text{Com}_j \land \text{Verify}(T, \pi_j, \text{Mau}(\varphi, \textbf{F}_j))$.
5. Each $P_i$ waits to receive $x_j^i$ from each other $P_j$.
6. Each $P_i$ sets $x_i := \sum_j x^i_j$, $X_j := \sum_i \textbf{F}_i^j$,
and $X := \sum_j \lambda(\mathcal{P})_j \cdot X_j$.
7. $\blacktriangle$ Each $P_i$ asserts that $x_i \cdot G = X_i$.
8. Each $P_i$ saves $x_i$, $[X_j \ |\ j \in [N]]$, and $X$.

**Output**

The value $x_i$ is $P_i$'s private share of the secret key $x$.

$X_j$ is the commitment to the private share $x_j$.

Finally $X$ is the public key shared by the group.
