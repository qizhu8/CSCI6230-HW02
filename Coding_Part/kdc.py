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


def assign_keys(conn, addr):
    print('Accept new connection from {0}'.format(addr));
    #conn.settimeout(500)
    conn.send(b'Hi, This is KDC. Waiting for your cipher key')
    buf = conn.recv(1024)
    while True:
        if buf:
            receive_packet = bytes.decode(buf).rstrip('\x00')
            print(receive_packet)

            reply_packet = kdc.process_packet(receive_packet)
            conn.send(reply_packet.encode())
            buf = conn.recv(1024)
        else:
            time.sleep(0.5)
    conn.close()
kdc = KDC(DES(), RSA(9973, 97))

# socket communication
host = 'localhost'
port = 9999

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(10)
except socket.error as msg:
    print(msg);
    sys.exit(1)
print('Waiting client connection...');


while 1:
    conn, addr = sock.accept()
    thread = threading.Thread(target=assign_keys, args=(conn, addr))
    thread.start()
