# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from PKC_Classes import NetworkUser, KDC
from DES import DES
from RSA_Class import RSA

import socket
import os
import sys
import threading
import time

if sys.version_info[0] < 3:
    raise Exception("Must be using Python 3")

def reply_conn(conn, addr):
    print('Accept new connection from user {0}'.format(addr));
    #conn.settimeout(500)
    # conn.send(b'Hi, This is bob. Waiting for your sess key')
    buf = conn.recv(1024)
    while True:
        if buf:
            receive_packet = bytes.decode(buf).rstrip('\x00')
            print('aaa', receive_packet)

            reply_packet = bob.process_packet(receive_packet)
            conn.send(reply_packet.encode())
            buf = conn.recv(1024)
        else:
            time.sleep(0.5)
    conn.close()

bob = NetworkUser('Alice', DES(), RSA(9973, 97), 200)
print('bob:', bob.uid)
# socket communication
kdc_host, kdc_port = 'localhost', 9999
bob_host, bob_port = 'localhost', 9200
# talk to kdc for sess key
try:
    sock_with_kdc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_with_kdc.connect((kdc_host, kdc_port))
    print(sock_with_kdc.recv(1024))
    # send cipher_key
    bob_cipher_key_packet = bob.send_cipher_key()
    sock_with_kdc.send(bob_cipher_key_packet.encode())

    kdc_bob_cipher_key_packet = sock_with_kdc.recv(1024).decode()
    print(kdc_bob_cipher_key_packet)
    bob.process_packet(kdc_bob_cipher_key_packet)

except socket.error as msg:
    print(msg);
    sys.exit(1)

# sock_with_kdc.shutdown(socket.SHUT_WR)

# talk to bob
try:
    sock_self = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_self.bind((bob_host, bob_port))
    sock_self.listen(10)

except socket.error as msg:
    print(msg);
    sys.exit(1)

while 1:
    conn, addr = sock_self.accept()
    thread = threading.Thread(target=reply_conn, args=(conn, addr))
    thread.start()

# sock_self.close()
