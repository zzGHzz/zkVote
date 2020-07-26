# Zero Knowledge Proof

## Proof of Knowledge

In cryptography, a proof of knowledge is an interactive proof in which the prover succeeds in 'convincing' a verifier that the prover knows something. What it means for a machine to 'know something' is defined in terms of computation. A machine 'knows something' if this something can be computed, given the machine as an input. As the program of the prover does not necessarily spit out the knowledge itself (as is the case for zero-knowledge proofs[1]) a machine with a different program, called the knowledge extractor is introduced to capture this idea. We are mostly interested in what can be proven by polynomial time bounded machines. In this case the set of knowledge elements is limited to a set of **witnesses** of some language in NP.

Let $x$ be a statement of language $L$ in NP, and $W(x)$ the set of witnesses for $x$ that should be accepted in the proof. This allows us to define the following relation: $R=\{(x,w):x\in L,w\in W(x)\}$.

A proof of knowledge for relation $R$ with knowledge error $\kappa$ is a two party protocol with a prover $P$ and a verifier $V$ with the following two properties:

* **Completeness**: if $(x,w)\in R$, $P$ who knows witness $w$ for $x$ to succeed in convincing $V$ of his knowledge. More formally: $\Pr(P(x,w)\leftrightarrow V(x) \rightarrow 1) =1$, i.e. given the interaction between $P$ and $V$, the probability that $V$ is convinced is 1.
* **Validity**: Validity requires that the success probability of a knowledge extractor $E$ in extracting the witness, given oracle access to a possibly malicious prover $\tilde{P}$, must be at least as high as the success probability of the prover $\tilde{P}$ in convincing $V$. This property guarantees that no prover that doesn't know the witness can succeed in convincing $V$.

## Decisional Diffie–Hellman Assumption

Consider a (multiplicative) cyclic group  $G$, and with generator $g$. The DDH assumption states that, given $g^a$ and $g^{b}$ for uniformly and independently chosen $a, b \in_R \mathbb{Z} _{q}$, the value $g^{ab}$ "looks like" a random element in $G$.

## Diffie-Hellman Key Exchange

Parties $\{\mathcal{P}_n\}_{n=1}^N$ agree on $(G, g, q)$. Each $\mathcal{P}_n$ generates secret $s_n\in_R\mathbb{Z}_q$. Starting from some party/parties sharing $g^{s_i}$, parties use their own secrets to sign some intermedia public info and propagate the signed value $g^{\prod_{i\in\Lambda}s_i}$ where $\Lambda$ is a subset of $\mathbb{Z}_N^*$. The eventual secret shared among the parties is $g^{\prod_n s_n}$.

## Proof of $x=\log_g[y=g^x]$ in [McCorryEtAl17]

1. Generate a random number $v$;
2. Calculate $r = v - x\cdot H(msg.sender,g^x,g^v)$ and give $(g^r,g^v)$ to the verifier where $H$ is any hash function;
3. Check whether $g^v=g^r\cdot (g^x)^{H(msg.sender,\,g^x,g^v)}$.

## Schnorr Protocol

$[x=\log_gy]$

1. The prover commits himself to randomness $v\in\mathbb{Z}_q^*$; therefore the first message to the verifier $t=g^{v}$ is also called commitment.
2. The verifier replies with a challenge $c$ chosen at random.
3. After receiving $c$, the prover sends the third and last message (the response) $s=g^{v-cx}$.

The verifier accepts, if $t=g^ry^c$.

**Protocols which have the above three-move structure (commitment, challenge and response) are called sigma ($\Sigma$) protocols**

## Fiat-Shamir Heuristic

$[x=\log_gy]$

1. The prover picks a random $v\in\mathbb{Z}_q^*$ and computes $t=g^v$.
2. The prover computes $c=H(g,y,t)$ where $H()$ is a cryptographic hash function.
3. The prover computes $r=v-cx$. The resulting proof is $(t,r)$.

Anyone can check whether $t=g^ry^c$.

**As long as a fixed random generator can be constructed with the data known to both parties, then any interactive protocol can be transformed into a non-interactive one.**

## Perderson Commitment

**Setup**: 
1. Large primes $p$ and $q$ such that $q\,\vert\,p-1$
2. Generator $g$ of the order-$q$ subgroup of $\mathbb{Z}_p^*$
3. $\alpha\in_R\mathbb{Z}_q$ and $h=g^\alpha\mod p$

Values $\{p,q,g,h\}$ are public and $\alpha$ is secret.

**Commit**: To commit $x\in\mathbb{Z}_q$,  the sender chooses $r\in_R\mathbb{Z}_q$ and sends $c=g^xh^r\mod p$ to the receiver.
**Reveal**: to open the commitment, the sender reveals $x$ and $r$, the receiver verifies that $c=g^xh^r \mod p$



<!--stackedit_data:
eyJoaXN0b3J5IjpbODc2NDAxODI4LDE5MjQxOTkzOTIsNDMzMT
c3MjI3LDE3MDQ0NzA5ODIsLTEzNjYxMTg2MTQsMTI4MzAzODE3
NiwtNTQ0Njc0MzI4XX0=
-->