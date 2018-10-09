# -*- coding: utf-8 -*-
#!/usr/bin/env python3
import time
from bidict import bidict
from DES import DES
import numpy as np
from RSA_Class import RSA

class NetworkUser(object):
    """docstring for NetworkUser."""
    def __init__(self, usernamd, encpt_obj, rsa_obj, uid=-1):
        super(NetworkUser, self).__init__()
        self.role = 'User'
        self.desc = ''
        self.action_codes = bidict({'SNT_CIPHER':'000', 'RPY_CIPHER':'001', 'REQ_KEY': '100', 'RPY_KEY': '200', 'REQ_CON': '300', 'RPY_CHLNG': '400', 'RPY_CLG_SOL': '500'})
        self.pkg_id = 0
        self.sess_key_info = {} # {uid_str: ['sess key', 'nonce', 'nonce2']}
        self.sess_ttl = 300 # time to live (sec)
        self.uid = (int(time.time()) + np.random.randint(1000)) % 1000 if uid == -1 else uid
        self.uname = usernamd
        self.packet_items = ['action_code', 'action_name', 'cipher_key', 'src_uid', 'dst_uid', 'nonce', 'encpt_KDC_rpy', 'encpt_sess_key_and_src_id_and_nonce', 'encpt_nonce', 'encpt_encpt_nonce']
        self.encpy_obj = encpt_obj # encryption and decryption method
        self.pv_key = None # generate private key
        self.RSA = rsa_obj

    def __str__(self):
        str_format = """name: {name}\nrole: {role}\nuid:  {uid}"""
        s = str_format.format(name=self.uname, role=self.role, uid=self.uid)
        return s + self.desc

    def gen_cipher_key(self): # note that, pv_key will change every time this function is called
        return self.RSA.gen_pv_key()

    def set_pv_key(self, cipher_key):
        shared_key = self.RSA.gen_shared_key(cipher_key)
        self.pv_key = self.encpy_obj.int_to_key(shared_key)

    def gen_nonce(self): # return a float number
        nonce = str(self.pkg_id) + '@' + str(time.time())
        return nonce

    def interp_nonce(self, nonce):
        nonce_elms = nonce.split('@')
        if len(nonce_elms) < 2:
            return None
        else:
            pkg_id = int(nonce_elms[0])
            ts = float(nonce_elms[1])
        return pkg_id, ts

    def change_rsa_key(self, k=1000):
        self.RSA.change_pv_key(k)

    # action_code, src_uid=-1, dst_uid=-1, nonce="", sess_key=0, encpt_sess_key_and_src_id_and_nonce="", encpt_nonce="", encpt_encpt_nonce=""
    def gen_packet(self, packet_info):
        # a general function to assemble pieces to package
        try:
            if 'action_code' in packet_info:
                action_code = packet_info['action_code']
                action_name = self.action_codes.inv[str(action_code)]
            elif 'action_name' in packet_info:
                action_name = packet_info['action_name']
                action_code = self.action_codes[action_name]
            else:
                print('action code/name unknown')
                return
        except Exception as e:
            print(e, 'action code/name not define')
            return
        packet_info['action_code'] = action_code
        packet_info['action_name'] = action_name

        try:
            if action_name == 'SNT_CIPHER':
                packet_format = "{action_code}||{src_uid}||{cipher_key}"
                packet = packet_format.format(\
                    action_code=packet_info['action_code'],
                    src_uid=packet_info['src_uid'],
                    cipher_key=packet_info['cipher_key'])
            elif action_name == 'RPY_CIPHER':
                packet_format = "{action_code}||{src_uid}||{cipher_key}"
                packet = packet_format.format(\
                    action_code=packet_info['action_code'],
                    src_uid=packet_info['src_uid'],
                    cipher_key=packet_info['cipher_key'])
            elif action_name == 'REQ_KEY':
                # request a key from KDC
                packet_format = "{action_code}||{src_uid}||{dst_uid}||{nonce}"
                packet = packet_format.format(\
                    action_code=packet_info['action_code'],
                    src_uid=packet_info['src_uid'],
                    dst_uid=packet_info['dst_uid'], nonce=packet_info['nonce'])
            elif action_name == 'RPY_KEY':
                # KDC reply beed to be excrypted
                packet_format = "{action_code}||{encpt_KDC_rpy}"
                packet = packet_format.format(\
                    action_code=packet_info['action_code'],
                    encpt_KDC_rpy=packet_info['encpt_KDC_rpy'])
            elif action_name == 'REQ_CON':
                # alice request to conect to bob
                packet_format = "{action_code}||{encpt_sess_key_and_src_id_and_nonce}"
                packet = packet_format.format(\
                    action_code=packet_info['action_code'],
                    encpt_sess_key_and_src_id_and_nonce=packet_info['encpt_sess_key_and_src_id_and_nonce'])
            elif action_name == 'RPY_CHLNG':
                packet_format = "{action_code}||{encpt_nonce}"
                packet = packet_format.format(\
                    action_code=packet_info['action_code'],
                    encpt_nonce=packet_info['encpt_nonce'])
            elif action_name == 'RPY_CLG_SOL':
                packet_format = "{action_code}||{src_uid}||{encpt_encpt_nonce}"
                packet = packet_format.format(\
                    action_code=packet_info['action_code'],
                    src_uid=packet_info['src_uid'],
                    encpt_encpt_nonce=packet_info['encpt_encpt_nonce'])
            else:
                print('action name ', action_name, ' unknown')
        except Exception as e:
            print(e, 'cannot generate packet')
            return None

        return packet

    def interp_packet(self, packet):
        if isinstance(packet, dict):
            return packet
        elif not isinstance(packet, str):
            print('Unknown packet type')
            return None
        packet_elems = packet.split('||')
        action_code = packet_elems[0]
        if action_code in self.action_codes.inv:
            action_name = self.action_codes.inv[action_code]
        else:
            print('action code/name unknown')
            return

        packet_info = self.gen_packet_dict()
        try:
            if action_name == 'SNT_CIPHER':
                packet_info['action_code'] = action_code
                packet_info['action_name'] = action_name
                packet_info['src_uid'] = int(packet_elems[1])
                packet_info['cipher_key'] = int(packet_elems[2])
            elif action_name == 'RPY_CIPHER':
                packet_info['action_code'] = action_code
                packet_info['action_name'] = action_name
                packet_info['src_uid'] = int(packet_elems[1])
                packet_info['cipher_key'] = int(packet_elems[2])
            elif action_name == 'REQ_KEY':
                # request a key from KDC
                # packet_format = "{action_code}||{src_uid}||{dst_uid}||{nonce}"
                packet_info['action_code'] = action_code
                packet_info['action_name'] = action_name
                packet_info['src_uid'] = int(packet_elems[1])
                packet_info['dst_uid'] = int(packet_elems[2])
                packet_info['nonce'] = packet_elems[3]
            elif action_name == 'RPY_KEY':
                # KDC reply beed to be excrypted
                packet_format = "{action_code}||{encpt_KDC_rpy}"
                packet_info['action_code'] = action_code
                packet_info['action_name'] = action_name
                packet_info['encpt_KDC_rpy'] = packet_elems[1]
            elif action_name == 'REQ_CON':
                # alice request to conect to bob
                packet_format = "{action_code}||{encpt_sess_key_and_src_id_and_nonce}"
                packet_info['action_code'] = action_code
                packet_info['action_name'] = action_name
                packet_info['encpt_sess_key_and_src_id_and_nonce'] = packet_elems[1]
            elif action_name == 'RPY_CHLNG':
                packet_format = "{action_code}||{encpt_nonce}"
                packet_info['action_code'] = action_code
                packet_info['action_name'] = action_name
                packet_info['encpt_nonce'] = packet_elems[1]
            elif action_name == 'RPY_CLG_SOL':
                packet_format = "{action_code}||{encpt_encpt_nonce}"
                packet_info['action_code'] = action_code
                packet_info['action_name'] = action_name
                packet_info['src_uid'] = int(packet_elems[1])
                packet_info['encpt_encpt_nonce'] = packet_elems[2]
            else:
                print('action name ', action_name, ' unknown')
        except Exception as e:
            print(e, 'cannot generate packet')
            return None
        return packet_info

    def gen_packet_dict(self):
        return {key:None for key in self.packet_items}

    def check_nonce(self, nonce):
        pkg_id, ts = self.interp_nonce(nonce)
        if (ts - time.time()) > self.sess_ttl:
            return False
        return True

    def send_cipher_key(self):
        packet_info = self.gen_packet_dict()
        user_cipher_key = self.gen_cipher_key()
        packet_info['action_name'] = 'SNT_CIPHER'
        packet_info['action_code'] = self.action_codes['SNT_CIPHER']
        packet_info['src_uid'] = self.uid
        packet_info['cipher_key'] = user_cipher_key

        packet = self.gen_packet(packet_info)
        return packet


    def request_key(self, dst_uid):
        nonce = self.gen_nonce()
        self.sess_key_info[str(dst_uid)] = [None, nonce, None]
        packet_info = self.gen_packet_dict()
        packet_info['action_name'] = 'REQ_KEY'
        packet_info['action_code'] = self.action_codes['REQ_KEY']
        packet_info['src_uid'] = self.uid
        packet_info['dst_uid'] = dst_uid
        packet_info['nonce'] = nonce

        packet = self.gen_packet(packet_info)
        return packet

    def request_connection(self, packet_REQ_KEY):
        if self.pv_key is None:
            print('Please share the private key with the KDC first!')
            return
        packet_REQ_KEY_info = self.interp_packet(packet_REQ_KEY)
        sess_key_src_id_and_nonce_bob_cipher = self.encpy_obj.decrypt(packet_REQ_KEY_info['encpt_KDC_rpy'], self.pv_key)
        encpt_KDC_rpy_elems = sess_key_src_id_and_nonce_bob_cipher.split('||')
        if len(encpt_KDC_rpy_elems) != 4:
            print('packet has been tampered!')
            return
        sess_key_str, bob_uid_str, nonce, bob_cipher = encpt_KDC_rpy_elems
        sess_key = self.encpy_obj.str_to_key_array(sess_key_str)

        if not self.check_nonce(nonce):
            print('session expires')
            return
        if bob_uid_str not in self.sess_key_info:
            print('didn''t request to connect to bob!')
            return
        if nonce != self.sess_key_info[bob_uid_str][1]:
            print('not the same nonce')
            return

        self.sess_key_info[bob_uid_str][0] = sess_key

        packet_info = self.gen_packet_dict()
        packet_info['action_name'] = 'REQ_CON'
        packet_info['action_code'] = self.action_codes['REQ_CON']
        packet_info['encpt_sess_key_and_src_id_and_nonce'] = bob_cipher

        packet = self.gen_packet(packet_info)
        return packet

    def reply_challenge(self, packet_REQ_CON_info):
        if self.pv_key is None:
            print('Please share the private key with the KDC first!')
            return

        request_connection = self.encpy_obj.decrypt(packet_REQ_CON_info['encpt_sess_key_and_src_id_and_nonce'], self.pv_key)
        request_connection_elems = request_connection.split('||')
        if len(request_connection_elems) != 3:
            print('packet has been tampered!')
            return
        sess_key_str, alice_uid_str, nonce = request_connection_elems
        sess_key = self.encpy_obj.str_to_key_array(sess_key_str)

        if not self.check_nonce(nonce):
            print('session expires')
            return

        nonce2 = self.gen_nonce()
        self.sess_key_info[alice_uid_str] = [sess_key, nonce, nonce2]
        encpt_nonce = self.encpy_obj.encrypt(nonce2, sess_key)

        packet_info = self.gen_packet_dict()
        packet_info['action_name'] = 'RPY_CHLNG'
        packet_info['action_code'] = self.action_codes['RPY_CHLNG']
        packet_info['encpt_nonce'] = encpt_nonce

        packet = self.gen_packet(packet_info)
        return packet

    def reply_challenge_sol(self, packet_RPY_CHLNG, bob_uid):
        packet_RPY_CHLNG_info = self.interp_packet(packet_RPY_CHLNG)
        sess_key = self.sess_key_info[str(bob_uid)][0]
        nonce2 = self.encpy_obj.decrypt(packet_RPY_CHLNG_info['encpt_nonce'], sess_key)
        perm_nonce2 = self.encpy_obj.encrypt(nonce2 + str(self.uid), sess_key)

        packet_info = self.gen_packet_dict()
        packet_info['action_name'] = 'RPY_CLG_SOL'
        packet_info['action_code'] = self.action_codes['RPY_CLG_SOL']
        packet_info['src_uid'] = self.uid
        packet_info['encpt_encpt_nonce'] = perm_nonce2

        packet = self.gen_packet(packet_info)
        return packet

    def check_challenge_sol(self, packet_RPY_CLG_SOL_info):
        alice_uid = packet_RPY_CLG_SOL_info['src_uid']
        sess_key = self.sess_key_info[str(alice_uid)][0]
        encpt_nonce = self.encpy_obj.decrypt(packet_RPY_CLG_SOL_info['encpt_encpt_nonce'], sess_key)

        encpt_nonce_self_cmp = self.sess_key_info[str(alice_uid)][2] + str(alice_uid)
        if encpt_nonce == encpt_nonce_self_cmp:
            return True
        else:
            return False

    def process_packet(self, packet):
        packet_info = self.interp_packet(packet)
        action_name = packet_info['action_name']

        if action_name == 'RPY_CIPHER':
            self.set_pv_key(packet_info['cipher_key'])
            print('user: ', self.uid, ' key: ', self.pv_key+0)
            print('Communicate the private key with KDC')
            return None
        elif action_name == 'REQ_CON':
            print('receive request for connection from ', packet_info['src_uid'])
            packet_RPY_CHLNG = self.reply_challenge(packet_info)
            return packet_RPY_CHLNG
        elif action_name == 'RPY_CLG_SOL':
            print('receive challenge solution from ', packet_info['src_uid'])
            check_challenge_sol_rst = self.check_challenge_sol(packet_info)
            if check_challenge_sol_rst:
                print('agree on connection with ', packet_info['src_uid'])
            else:
                print('deny on connection with ', packet_info['src_uid'])
            return str(check_challenge_sol_rst+0)
        else:
            print('action name ', action_name, ' unknown')

class KDC(NetworkUser):
    """docstring for KDC."""
    def __init__(self, encpy_obj, rsa_obj):
        super(KDC, self).__init__('KDC', encpy_obj, rsa_obj)
        self.role = 'KDC'
        self.user_key_dict = {}

    def gen_pv_key(self, cipher_key):
        return self.RSA.gen_shared_key(cipher_key)

    def gen_sess_key(self):
        return self.encpy_obj.gen_key()

    def add_user_encpt_info(self, uid, cipher_key):
        shared_key = self.gen_pv_key(cipher_key)
        self.user_key_dict[str(uid)] = self.encpy_obj.int_to_key(shared_key)

    def reply_cipher_key(self, user_cipher_key_packet_info):
        kdc_user_cipher_key = self.gen_cipher_key() # regenerate a cipher key
        src_uid = user_cipher_key_packet_info['src_uid']
        self.add_user_encpt_info(src_uid, user_cipher_key_packet_info['cipher_key'])
        print('kdc add user: ', src_uid, ' key: ', self.user_key_dict[str(src_uid)]+0)

        # format the packet
        packet_info = self.gen_packet_dict()
        packet_info['action_name'] = 'RPY_CIPHER'
        packet_info['action_code'] = self.action_codes['RPY_CIPHER']
        packet_info['src_uid'] = self.uid
        packet_info['cipher_key'] = kdc_user_cipher_key
        packet = self.gen_packet(packet_info)
        return packet


    def reply_sess_key(self, req_key_packet_info):
        nonce = req_key_packet_info['nonce']
        alice_uid_str, bob_uid_str = str(req_key_packet_info['src_uid']), str(req_key_packet_info['dst_uid'])

        print(alice_uid_str, ' would like to talk to ', bob_uid_str)
        # check nonce validation
        if not self.check_nonce(nonce):
            print('session expires')
            return

        if alice_uid_str not in self.user_key_dict:
            print('KDC doesn''t have requester''s key')
            return
        alice_key = self.user_key_dict[alice_uid_str]

        if bob_uid_str not in self.user_key_dict:
            print('KDC doesn''t have destination''s key')
            return
        bob_key = self.user_key_dict[bob_uid_str]

        # gen bob's sess+key
        sess_key_str = self.encpy_obj.key_array_to_str(self.gen_sess_key())
        sess_key_src_id_and_nonce = sess_key_str + '||' + alice_uid_str + '||' + nonce
        bob_enc_sess_key_src_id_and_nonce = self.encpy_obj.encrypt(sess_key_src_id_and_nonce, bob_key)

        # gen alice's reply
        sess_key_src_id_and_nonce_bob_cipher = sess_key_str + '||' + bob_uid_str + '||' + nonce + '||' + bob_enc_sess_key_src_id_and_nonce
        alice_enc_sess_key_src_id_and_nonce_bob_cipher = self.encpy_obj.encrypt(sess_key_src_id_and_nonce_bob_cipher, alice_key)

        # format the packet
        packet_info = self.gen_packet_dict()
        packet_info['action_name'] = 'RPY_KEY'
        packet_info['action_code'] = self.action_codes['RPY_KEY']
        packet_info['encpt_KDC_rpy'] = alice_enc_sess_key_src_id_and_nonce_bob_cipher

        packet = self.gen_packet(packet_info)
        return packet

    def process_packet(self, packet):
        packet_info = self.interp_packet(packet)
        action_name = packet_info['action_name']

        if action_name == 'SNT_CIPHER':
            packet = self.reply_cipher_key(packet_info)
        elif action_name == 'REQ_KEY':
            packet = self.reply_sess_key(packet_info)
        else:
            print('action name ', action_name, ' not suitable')
        return packet
