# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from PKC_Classes import NetworkUser, KDC
from DES import DES
from RSA_Class import RSA

import socket
import os
import sys
import time

if sys.version_info[0] < 3:
    raise Exception("Must be using Python 3")

alice = NetworkUser('Alice', DES(), RSA(9973, 97), 100)
print('alice:', alice.uid)
# socket communication
kdc_host, kdc_port = 'localhost', 9999
bob_host, bob_port = 'localhost', 9200
bob_uid = 200
# talk to kdc for sess key
try:
    sock_with_kdc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_with_kdc.connect((kdc_host, kdc_port))
    print(sock_with_kdc.recv(1024))
    # send cipher_key
    alice_cipher_key_packet = alice.send_cipher_key()
    sock_with_kdc.send(alice_cipher_key_packet.encode())

    kdc_alice_cipher_key_packet = sock_with_kdc.recv(1024).decode()
    print(kdc_alice_cipher_key_packet)
    alice.process_packet(kdc_alice_cipher_key_packet)

    # ask for bob's sess key
    print('ask for the sess key to talk to ', bob_uid)
    packet_REQ_KEY = alice.request_key(bob_uid)
    sock_with_kdc.send(packet_REQ_KEY.encode())
    packet_RPY_KEY = sock_with_kdc.recv(1024).decode()

    print(packet_RPY_KEY)
except socket.error as msg:
    print(msg);
    sys.exit(1)

# sock_with_kdc.shutdown(socket.SHUT_WR)

# talk to bob
try:
    sock_self = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_self.connect((bob_host, bob_port))
    print('connected with bob')
    # talk to bob
    packet_REQ_CON = alice.request_connection(packet_RPY_KEY)
    sock_self.send(packet_REQ_CON.encode())
    packet_RPY_CHLNG = sock_self.recv(1024).decode()

    packet_RPY_CHLNG_SOL = alice.reply_challenge_sol(packet_RPY_CHLNG, bob_uid)
    sock_self.send(packet_RPY_CHLNG_SOL.encode())
    print(sock_with_kdc.recv(1024))
    print('finish task')
except socket.error as msg:
    print(msg);
    sys.exit(1)

sock_with_kdc.shutdown(socket.SHUT_WR)
sock_self.shutdown(socket.SHUT_WR)
sock_with_kdc.close()
sock_self.close()
