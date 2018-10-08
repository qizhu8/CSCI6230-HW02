# CSCI6230-HW02

## Abstract
This homework simulates the scenario where two users need to agree with a shared session key. The key sharing is achieved with the help of Key Distribution Center(KDC).
Alice and bob first share their individual private keies with KDC using Computational Deffie-Hellman key exchange protocol. Then, the session starter, alice, follows Needham-Schroeder Symmetric Key Protocol(N-S) to agree on a session key with bob. The N-S protocol implemented is resistant to replay attack.

## I. System Setup
In the network, there are two roles: users and KDC.
KDC is a Key Distribution Center. All users and the KDC are connected in the network. When one user, say user Alice, wants to talk to another user, say Bob, both Alice and Bob must agree on a shared symmetric session key to protect the following commnunication. The session key used by both Alice and Bob is assigned by the KDC following Needham-Schroeder Symmetric Key Protocol.

According to the implementation of N-S protocol, KDC needs to know the private keys of all users. The key sharing between user and the KDC is realized applying Computational Deffie-Hellman key exchange protocol.

The adversary in the network is considered to have the ability to conduct replay attact.

## II. How It is Implemented
In the simulation, there are three entities: Alice, Bob and the KDC.
The simulation can be divided into two stages:
### II.1 Stage One: Private Key Sharing
In this stage, Alice and Bob use computational D-H protocol to share their private keys to the KDC repectively. The private key is a 10-bit binary number which is used to implement the DES encryption in stage two. The following is the decription of the steps that Alice and the KDC do to share the key. The key sharing between Bob and the KDC is exactly the same.

Initially, all users and the KDC agree on two big prime numbers $q$ and $\alpha$.
Alice first generates a random integer $m_A \in [0, q]$ and sends $y_A = \alpha^{m_A}~mod~q$ to the KDC.

After receiving $y_A$, the KDC generates another random integer $m_K \in [0, q]$, save $y_A^{m_K}$ and Alice's id to its memory. $K_{AK} = y_A^{m_K}~mod~q$ is the private key for Alice. The KDC sends $y_K = \alpha^{m_K}$ to Alice.

Alice receives the KDC's reply $y_K$ and uses $K_{AK}' = y_K^{m_A}~mod~q$ as its private key.
Note that $K_{AK} = K_{AK}'$ because
- <img src="https://latex.codecogs.com/gif.latex?O_t=K_{AK} = y_A^{m_K}~mod~q = (\alpha^{m_A})^{m_K}~mod~q = \alpha^{m_A \cdot m_K}~mod~q = (\alpha^{m_K})^{m_A}~mod~q = (y_K)^{m_A}~mod~q = K_{AK}' t " /> 
