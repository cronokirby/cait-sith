Given a set of players $\mathcal{P} = \{P_1, \ldots, P_N\}$,
and a desired threshold $t$, define
the following protocol:

### KeyGen


**Round 1:**

1. $\blacktriangle$ Each $P_i$ *asserts* that $|\mathcal{P}| \geq t$.
2. $T.\text{Add}(\mathcal{P}, t)$
3. Each $P_i$ generates $f_0, \ldots, f_{t - 1} \xleftarrow{R} \mathbb{F}_q$, defining a polynomial $f$.
4. Each $P_i$ sets $\textbf{F}_ i \gets \varphi(f)$ where:

$$
\varphi(f) := [f(0) \cdot G]\ ||\ \left[f(j) \cdot G \ |\ P_j \in \mathcal{P} \right]
$$

5. Each $P_i$ sets $\text{Com}_i \gets H(\textbf{F}_i)$.
6. $\star$ Each $P_i$ sends $\text{Com}_i$ to every other party.

**Round 2:**

1. $\bullet$ Each $P_i$ waits to receive $\text{Com}_j$ from each other $P_j$.
2. Each $P_i$ sets $\text{Confirm}_i \gets H(\text{Com}_1, \ldots, \text{Com}_N)$.
3. $T.\text{Add}(\text{Confirm}_i)$
4. $\star$ Each $P_i$ sends $\text{Confirm}_i$ to every other party.
5. Each $P_i$ generates the proof $\pi_i \gets \text{Prove}(T, \text{Mau}(\varphi, \textbf{F}_i; f))$
6. $\star$ Each $P_i$ sends $(\textbf{F}_i, \pi_i)$ to every other party.
7. $\textcolor{red}{\star}$ Each $P_i$ *privately* sends $x_i^j := f(j)$ to each other party $P_j$, and saves $x_i^i$ for itself.

**Round 3:**

1. $\bullet$ Each $P_i$ waits to receive $\text{Confirm}_j$ from each other $P_j$.
2. $\blacktriangle$ Each $P_i$ *asserts* that $\forall j \in [N].\ \text{Confirm}_j = \text{Confirm}_i$, aborting otherwise.
3. $\bullet$ Each $P_i$ waits to receive $(\textbf{F}_j, \pi_j)$ from each other $P_j$.
4. $\blacktriangle$ Each $P_i$ *asserts* that $\forall j \in [N].\ H(\textbf{F}_j) = \text{Com}_j \land \text{Verify}(T, \pi_j, \text{Mau}(\varphi, \textbf{F}_j))$.
5. $\bullet$ Each $P_i$ waits to receive $x_j^i$ from each other $P_j$.
6. Each $P_i$ sets $x_i := \sum_j x^i_j$ and $X := \sum_j \textbf{F}_j^0$.
7. $\blacktriangle$ Each $P_i$ asserts that $x_i \cdot G = \sum_j \bold{F}_j^i$.
8. Each $P_i$ outputs $x_i$ and $X$.

**Output**

The value $x_i$ is $P_i$'s private share of the secret key $x$.

$X$ is the public key shared by the group.
