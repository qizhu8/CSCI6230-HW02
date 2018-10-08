#!/usr/bin/env python3

from PKC_Classes import NetworkUser, KDC
from DES import DES
from RSA_Class import RSA

alice = NetworkUser('Alice', DES(), RSA(9973, 97))
bob = NetworkUser('Bob', DES(), RSA(9973, 97))
kdc = KDC(DES(), RSA(9973, 97))


# order CANNOT be changed. KDC's RSA private key is changed every time gen_cipher_key() is called
alice_cipher_key_packet = alice.send_cipher_key()
bob_cipher_key_packet = bob.send_cipher_key()
kdc_alice_cipher_key_packet = kdc.process_packet(alice_cipher_key_packet)
kdc_bob_cipher_key_packet = kdc.process_packet(bob_cipher_key_packet)

alice.process_packet(kdc_alice_cipher_key_packet)
bob.process_packet(kdc_bob_cipher_key_packet)


packet_REQ_KEY = alice.request_key(bob.uid)
print(packet_REQ_KEY)

packet_RPY_KEY = kdc.process_packet(packet_REQ_KEY)
print(packet_RPY_KEY)

packet_REQ_CON = alice.request_connection(packet_RPY_KEY)
print(packet_REQ_CON)

packet_RPY_CHLNG = bob.process_packet(packet_REQ_CON)
print(packet_RPY_CHLNG)

packet_RPY_CLG_SOL = alice.reply_challenge_sol(packet_RPY_CHLNG, bob.uid)
print(packet_RPY_CLG_SOL)

bob.process_packet(packet_RPY_CLG_SOL)
