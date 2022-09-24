This document specifies the signing protocol.
The protocol is split into two main phases, a pre-signing phase

# 1 Preliminaries

Let $\mathbb{G}$ be a cryptographic group, with generator $G$, of prime order $q$.

Let $\text{Hash} : \{0, 1\}^* \to \mathbb{F}_q$ denote a hash function used for hashing messages
for signatures.
Let $h : \mathbb{G} \to \mathbb{F}_q$ denote a different "hash function" used for converting points to scalars.
Commonly, this is done by "simply" taking the x coordinate of the affine
representation of a point.

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