# CSCI6230-HW02

## Abstract
This homework simulates the scenario where two users need to agree with a shared session key. The key sharing is achieved with the help of Key Distribution Center(KDC).
Alice and bob first share their individual private keies with KDC using Computational Deffie-Hellman key exchange protocol. Then, the session starter, alice, follows Needham-Schroeder Symmetric Key Protocol(N-S) to agree on a session key with bob. The N-S protocol implemented is resistant to replay attack.

## I. System Setup
In the network, there are two roles: users and KDC.
KDC is a Key Distribution Center. All users and the KDC are connected in the network. When one user, say user Alice, wants to talk to another user, say Bob, both Alice and Bob must agree on a shared symmetric session key to protect the following commnunication. The session key used by both Alice and Bob is assigned by the KDC following Needham-Schroeder Symmetric Key Protocol.

According to the implementation of N-S protocol, KDC needs to know the private keys of all users. The key sharing between user and the KDC is realized applying Computational Deffie-Hellman key exchange protocol.

The adversary in the network is considered to have access to the ciphertex and is able to conduct replay attact.

## II. How It is Implemented
In the simulation, there are three entities: Alice, Bob and the KDC.
The simulation can be divided into two stages:
### II.1 Stage One: Private Key Sharing
In this stage, Alice and Bob use computational D-H protocol to share their private keys to the KDC repectively. The private key is a 10-bit binary number which is used to implement the DES encryption in stage two. The following is the decription of the steps that Alice and the KDC do to share the key. The key sharing between Bob and the KDC is exactly the same.

Initially, all users and the KDC agree on two big prime numbers <img src="http://latex.codecogs.com/gif.latex?q" title="q" /> and <img src="http://latex.codecogs.com/gif.latex?\alpha" title="\alpha" />.
Alice first generates a random integer <img src="http://latex.codecogs.com/gif.latex?m_A&space;\in&space;[0,&space;q]" title="m_A \in [0, q]" /> and sends <img src="http://latex.codecogs.com/gif.latex?y_A&space;=&space;\alpha^{m_A}~mod~q" title="y_A = \alpha^{m_A}~mod~q" /> to the KDC.

After receiving <img src="http://latex.codecogs.com/gif.latex?y_A" title="y_A" />, the KDC generates another random integer <img src="http://latex.codecogs.com/gif.latex?m_K&space;\in&space;[0,&space;q]" title="m_K \in [0, q]" />, save <img src="http://latex.codecogs.com/gif.latex?y_A^{m_K}" title="y_A^{m_K}" /> and Alice's id to its memory. <img src="http://latex.codecogs.com/gif.latex?K_{AK}&space;=&space;y_A^{m_K}~mod~q" title="K_{AK} = y_A^{m_K}~mod~q" /> is the private key for Alice. The KDC sends <img src="http://latex.codecogs.com/gif.latex?y_K&space;=&space;\alpha^{m_K}" title="y_K = \alpha^{m_K}" /> to Alice.

Alice receives the KDC's reply $y_K$ and uses <img src="http://latex.codecogs.com/gif.latex?K_{AK}'&space;=&space;y_K^{m_A}~mod~q" title="K_{AK}' = y_K^{m_A}~mod~q" /> as its private key.
Note that <img src="http://latex.codecogs.com/gif.latex?K_{AK}&space;=&space;K_{AK}'" title="K_{AK} = K_{AK}'" /> because

<img src="http://latex.codecogs.com/gif.latex?K_{AK}&space;=&space;y_A^{m_K}~mod~q&space;=&space;(\alpha^{m_A})^{m_K}~mod~q&space;=&space;\alpha^{m_A&space;\cdot&space;m_K}~mod~q&space;=&space;(\alpha^{m_K})^{m_A}~mod~q&space;=&space;(y_K)^{m_A}~mod~q&space;=&space;K_{AK}'" title="K_{AK} = y_A^{m_K}~mod~q = (\alpha^{m_A})^{m_K}~mod~q = \alpha^{m_A \cdot m_K}~mod~q = (\alpha^{m_K})^{m_A}~mod~q = (y_K)^{m_A}~mod~q = K_{AK}'" />

Suppose the adversary captures the two packets $y_A$ and $y_K$, and it also knows $q$ and $\alpha$. In order to know the key $K_{AK}$, it has to solve two descrete logarithm problems $m_A = \log_{\alpha} y_A~mod~q$ and $m_K = \log_{\alpha} y_K~mod~q$, which are computational difficult.

After this stage, both Alice and Bob have their own keys, and their keys are known by only the KDC and themselves.

### II.2 Stage Two: Session Key Sharing
In stage two, Alice asks the KDC to assgin a session key for the commnunication session between Alice and Bob and she sends the packet containing the session key to Bob and passes the verification test by Bob. Then a connection using the session key is built. The key sharing follows six steps:

1. Alice tells the KDC to assign a session key to talk to Bob
2. KDC replies an encrypted packet with the session key and a cipher to Bob
3. Alice decrypts the packet, notes down the session key and sends the cipher to Bob
4. Bob decrpts the cipher, notes down the session key and sends an encrypted nonce to Alice to verify that Alice knows the session key
5. Alice decrypts the nonce and applys a known permutation of the nonce and sends it back encrypted with the session key
6. Bob checks the result and starts connecting with Alice if Alice passes the verification
