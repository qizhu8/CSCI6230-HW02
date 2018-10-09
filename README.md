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

Alice receives the KDC's reply <img src="http://latex.codecogs.com/gif.latex?y_K" title="y_K" /> and uses <img src="http://latex.codecogs.com/gif.latex?K_{AK}'&space;=&space;y_K^{m_A}~mod~q" title="K_{AK}' = y_K^{m_A}~mod~q" /> as its private key.
Note that <img src="http://latex.codecogs.com/gif.latex?K_{AK}&space;=&space;K_{AK}'" title="K_{AK} = K_{AK}'" /> because

<img src="http://latex.codecogs.com/gif.latex?K_{AK}&space;=&space;y_A^{m_K}~mod~q&space;=&space;(\alpha^{m_A})^{m_K}~mod~q&space;=&space;\alpha^{m_A&space;\cdot&space;m_K}~mod~q&space;=&space;(\alpha^{m_K})^{m_A}~mod~q&space;=&space;(y_K)^{m_A}~mod~q&space;=&space;K_{AK}'" title="K_{AK} = y_A^{m_K}~mod~q = (\alpha^{m_A})^{m_K}~mod~q = \alpha^{m_A \cdot m_K}~mod~q = (\alpha^{m_K})^{m_A}~mod~q = (y_K)^{m_A}~mod~q = K_{AK}'" />

Suppose the adversary captures the two packets <img src="http://latex.codecogs.com/gif.latex?y_A" title="y_A" /> and <img src="http://latex.codecogs.com/gif.latex?y_K" title="y_K" />, and it also knows <img src="http://latex.codecogs.com/gif.latex?q" title="q" /> and <img src="http://latex.codecogs.com/gif.latex?\alpha" title="\alpha" />. In order to know the key <img src="http://latex.codecogs.com/gif.latex?K_{AK}" title="K_{AK}" />, it has to solve two descrete logarithm problems <img src="http://latex.codecogs.com/gif.latex?m_A&space;=&space;\log_{\alpha}&space;y_A~mod~q" title="m_A = \log_{\alpha} y_A~mod~q" /> and <img src="http://latex.codecogs.com/gif.latex?m_K&space;=&space;\log_{\alpha}&space;y_K~mod~q" title="m_K = \log_{\alpha} y_K~mod~q" />, which are computational difficult.

After this stage, both Alice and Bob have their own keys, and their keys are known by only the KDC and themselves.

### II.2 Stage Two: Session Key Sharing
In stage two, Alice asks the KDC to assgin a session key for the commnunication session between Alice and Bob and she sends the packet containing the session key to Bob and passes the verification test by Bob. Then a connection using the session key is built. The key sharing follows six steps:

1. Alice tells the KDC to assign a session key to talk to Bob

<img src="http://latex.codecogs.com/gif.latex?Alice&space;\rightarrow&space;KDC:~ID_A&space;||&space;ID_B&space;||&space;N_1" title="Alice \rightarrow KDC:~ID_A || ID_B || N_1" />
<img src="http://latex.codecogs.com/gif.latex?ID_A" title="ID_A" />, <img src="http://latex.codecogs.com/gif.latex?ID_B" title="ID_B" /> and <img src="http://latex.codecogs.com/gif.latex?N_1" title="N_1" /> are the id for Alice, the id for Bob and nonce repectively. <img src="http://latex.codecogs.com/gif.latex?||" title="||" /> is the notation meaning the entity on the right side of the notation is concatenated to the end of the left side entity.

2. KDC replies an encrypted packet with the session key and a cipher to Bob
The packet structure is

<img src="http://latex.codecogs.com/gif.latex?KDC&space;\rightarrow&space;Alice:~E_{K_{AK}}[K_S&space;||&space;ID_B&space;||&space;N_1&space;||&space;E_{K_{BK}}[K_S&space;||&space;ID_A&space;||&space;N_1]]" title="KDC \rightarrow Alice:~E_{K_{AK}}[K_S || ID_B || N_1 || E_{K_{BK}}[K_S || ID_A || N_1]]" />

<img src="http://latex.codecogs.com/gif.latex?E_{K}[x]" title="E_{K}[x]" /> is used to denote the encryption operation using key <img src="http://latex.codecogs.com/gif.latex?K" title="K" /> to plaintext <img src="http://latex.codecogs.com/gif.latex?x" title="x" />.

3. Alice decrypts the packet, notes down the session key and sends the cipher to Bob

<img src="http://latex.codecogs.com/gif.latex?Alice&space;\rightarrow&space;Bob:~E_{K_{BK}}[K_S&space;||&space;ID_A&space;||&space;N_1]]" title="Alice \rightarrow Bob:~E_{K_{BK}}[K_S || ID_A || N_1]]" />

4. Bob decrpts the cipher, notes down the session key and sends an encrypted nonce to Alice to verify that Alice knows the session key

<img src="http://latex.codecogs.com/gif.latex?Bob&space;\rightarrow&space;Alice:~E_{K_S}[N_2]]" title="Bob \rightarrow Alice:~E_{K_S}[N_2]]" />

5. Alice decrypts the nonce and applys a known permutation of the nonce and sends it back encrypted with the session key

<img src="http://latex.codecogs.com/gif.latex?Alice&space;\rightarrow&space;Bob:~E_{K_S}[N_2||ID_A]]" title="Alice \rightarrow Bob:~E_{K_S}[N_2||ID_A]]" />

6. Bob checks the result and starts connecting with Alice if Alice passes the verification

This implementation of protocol can resist the replay attacks because all the transmissions contains nonces. If the receiver find that the nonce of the packet belongs to an expired packet, this packet is considered to be invalid. The attacker cannot replay any used packet to build a connection.

## Code Details
Each packet contains an action id and payload. Action id is a three digit number indicating the function of this packet.

| Action Code | Description                                   |
|-------------|-----------------------------------------------|
| 000         | User sends key to KDC (stage 1-1)             |
| 001         | KDC replies key to the user (stage 1-2)       |
| 100         | Alice requests session key (stage 2-1)        |
| 200         | KDC replies encrypted session key (stage 2-2) |
| 300         | Alice requests to connect to Bob (stage 2-3)  |
| 400         | Bob sends encrypted challenge (stage 2-4)     |
| 500         | Alice replies solved challenge (stage-5)      |

The payload of each packet contains the message to be sent. For example, in stage 2-3, Alice sends the ciphertext to Bob, the packet structure is "300||[ciphertext]".

KDC keeps listening to users' key sharing requests (stage 1). Once Alice or Bob connects to the network, the first tast is to share its private key with the KDC.
IDs for Alice and Bob are 100 and 200 repectively.

After that, Bob waits for other users' (Alice in this simulation) connection requests， while Alice sends KDC the request to connect to Bob. The symmetric key encryption method is DES, which is implemented in HW01. The rest communications follow exactly as the description in Stage 2.

## How to Run
First, run the KDC
```bash
python3 kdc.py
```
Then, run Bob
```bash
python3 bob.py
```
finally run Alice
```bash
python3 alice.py
```

The terminal for KDC will show something like
```bash
Waiting client connection...
Accept new connection from ('127.0.0.1', 54272)
000||200||4724
kdc add user:  200  key:  [1 1 1 0 1 0 1 1 0 0]
Accept new connection from ('127.0.0.1', 54273)
000||100||5348
kdc add user:  100  key:  [1 0 1 0 0 1 0 0 1 0]
100||100||200||0@1539047943.174232
100  would like to talk to  200
```

The terminal for Bob is expected to see
```bash
bob: 200
b'Hi, This is KDC. Waiting for your cipher key'
001||317||3225
user:  200  key:  [1 1 1 0 1 0 1 1 0 0]
Communicate the private key with KDC
Accept new connection from user ('127.0.0.1', 54274)
aaa 300||kLLLLkLLLL§§kLL§§LÁkÎPL	`P	}k`	µµ
receive request for connection from  None
aaa 500||100||<|·6
<}¯}
Ò__··}·<<
receive challenge solution from  100
agree on connection with  100
```
The teriminal for Alice shows
```bash
alice: 100
b'Hi, This is KDC. Waiting for your cipher key'
001||317||9799
user:  100  key:  [1 0 1 0 0 1 0 0 1 0]
Communicate the private key with KDC
ask for the sess key to talk to  200
200||¹2222¹2222ÿÿC22ÿÿ23¹8W2s[Ws¹[sCCÿÿööööv1AþþAþA
connected with bob
```
