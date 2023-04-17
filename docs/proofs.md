Various protocols use ZK proofs using the Fiat-Shamir
These proofs need to incorporate as much contextual information as necessary to avoid potential replay attacks.
To accomplish this, we use a "transcript" abstraction, which allows absorbing information before then using it in a proof.

# Transcript API

- $T.\text{Add}(x_1, x_2, \ldots)$ absorbs new data $x_1, x_2, \ldots$, handling separation and padding.
- $T.\text{Cloned}(\text{tag}, x_1, \ldots)$ produces a forked version of the transcript, by using a given tag, and additional data. This transcript will not modify the original transcript $T$, but will contain the information absorbed in it.

You can also think of a transcript as essentially containing a complete
list of all the operations performed on it.
So adding $x$ and then $y$ is equivalent to having a transcript consisting
of $[x, y]$.
All this information will then be used when the transcript is passed
to create or verify a proof.

This transcript API is closely related to the implementation
used in this library: [Magikitten](https://github.com/cronokirby/magikitten).
Looking at the API of that library will likely make this
API more understandable.

# ZK Proofs

The proofs we use in this library are all Maurer proofs.
These are proofs of the form:
"I know a secret $x$ such that $\varphi(x) = X$, with $X$ a public value",
and $\varphi$ being a homomorphism, i.e. $\varphi(a + b) = \varphi(a) + \varphi(b)$.

A common case of this is the Schnorr discrete logarithm proof,
with $\varphi(x) = x \cdot G$.
We would write this as $- \cdot G$ in the notation of our specifications.

In general, we write $\text{Mau}(\varphi, X; x)$
to denote the relation "I know a private $x$ such that $\varphi(x) = X$.
We also write $\text{Mau}(\varphi, X)$ to denote the verifier's
view of this relation, where $x$ is not known.

Using this notation, we write:
- $$
\text{Prove}(T, \text{Mau}(\varphi, X; x))
$$
- $$
\text{Verify}(T, \pi, \text{Mau}(\varphi, X))
$$
for creating and verifying a proof, using a transcript for binding
proofs to a given context.

See [this blog post](https://cronokirby.com/posts/2022/08/the-paper-that-keeps-showing-up/) for more context on Maurer proofs.
