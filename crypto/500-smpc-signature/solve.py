#!/usr/bin/env python
from base64 import b64decode
from itertools import combinations
from functools import reduce
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import derive_private_key, SECP256K1
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from random import randint

import argparse
import hashlib
import json
import re
import fastecdsa.curve
import fastecdsa.point


SECP256K1_CURVE = fastecdsa.curve.secp256k1
SECP256K1_ORDER = SECP256K1_CURVE.q

assert SECP256K1_ORDER == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

DATA_TO_SIGN = "👋 Hello, world 🌍 🎉".encode("utf-8")

PUBLIC_KEY_PEM = b"""
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEvKsN5HwvH71x0hB2omeCdiQRBy9PqSKi
k8b4gRRkyHnYQYKnBHwzErzm2zuvLY07bsY1eZ9CILDvbMwgct1ATA==
-----END PUBLIC KEY-----
"""

############################### Some useful math functions ###############################

def egcd(a, b):
    """
    Extended gcd
    https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    """
    Modular inverse 
    https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
    """
    g, x, y = egcd(a, m)
    if g != 1:
        print(g)
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def pollar_rho(n, A):
    """
    Find factor using pollar rho method
    """
    a, b = 2, 2
    d = 1
    g = lambda x: (x**2 + A) % n

    while d == 1:
        a, b = g(a), g(g(b))
        d = gcd(abs(b - a), n)

    if d == 1:
        return -1

    return d

def is_prime(x):
    """
    Fermat primality check
    """
    if x < 4:
        return True
    a = randint(2, x - 2)
    return pow(a, x - 1, x) == 1

def decompose_prime(x, A = 1):
    """
    Decompose a number x in product of prime numbers
    """
    l = []
    while x != 1:
        if x % 2 == 0:
            factor = 2
        else:
            factor = pollar_rho(x, A)
        if is_prime(factor):
            l.append(factor)
        else:
            l += decompose_prime(factor, A + 1)
        x //= factor
    return l

def sss_recover(shares, x):
    """
    Reconstruct the secret using naive implementation of Shamir's Secret Sharing
    """
    value = 0
    for x_i, y_i in shares:
        term_i = y_i
        for x_j, _ in shares:
            if x_i == x_j:
                continue
            # inv_ij = pow(x_j - x_i, -1, SECP256K1_ORDER)
            inv_ij = modinv((x_j - x_i) % SECP256K1_ORDER, SECP256K1_ORDER)
            term_i = (term_i * (x_j - x) * inv_ij) % SECP256K1_ORDER
        value = (value + term_i) % SECP256K1_ORDER
    return value

############################### Logfile parsing functions ###############################

class MessageBuilder:
    """
    Simple message builder class
    """

    @staticmethod
    def new_message(msg_type, *kargs, **kwargs):
        if msg_type == Message.START_SERVER:
            return StartServerMessage(*kargs, **kwargs)
        elif msg_type == Message.SIGN:
            return SignMessage(*kargs, **kwargs)
        elif msg_type == Message.SEND_PACKET:
            return SendPacketMessage(*kargs, **kwargs)
        elif msg_type == Message.CONNECTION:
            return ConnectionMessage(*kargs, **kwargs)
        elif msg_type == Message.SIGNATURE:
            return SignatureMessage(*kargs, **kwargs)
        else:
            raise NotImplemented

class Message:
    """
    Generique class for message
    """

    START_SERVER = 0
    SIGN         = 1
    SEND_PACKET  = 2
    CONNECTION   = 3
    SIGNATURE    = 4

    def __init__(self):
        pass

class StartServerMessage(Message):
    def __init__(self, *kargs, **kwargs):
        self.x      = int(kwargs["x"])
        self.ip     = kwargs["ip"]
        self.port   = int(kwargs["port"])
        self.pubkey = kwargs["pubkey"]

class SignMessage(Message):
    def __init__(self, *kargs, **kwargs):
        self.x       = int(kwargs["x"])
        self.payload = json.loads(kwargs["payload"].replace("'", '"'))

class ConnectionMessage(Message):
    def __init__(self, *kargs, **kwargs):
        self.x       = int(kwargs["x"])
        self.n       = int(kwargs["n"])
        self.nodes   = kwargs["nodes"]

class SignatureMessage(Message):
    def __init__(self, *kargs, **kwargs):
        self.signature = bytes.fromhex(kwargs["signature"])

class SendPacketMessage(Message):
    def __init__(self, *kargs, **kwargs):
        self.x       = int(kwargs["x"])
        self.size    = int(kwargs["size"])
        self.x_from  = int(kwargs["x_src"])
        self.x_to    = int(kwargs["x_dst"])
        self.payload = bytes.fromhex(kwargs["hexdata"])

class LogParser:
    """
    Simple class to parse the SMPC log file
    """

    RE_START       = r"^\[\s*([0-9]+) .+\] "
    RE_STARTSERVER = RE_START + r"Started server on (.*):([0-9]+) with public key (.*)$"
    RE_SIGNCMD     = RE_START + r"Received SIGN command (.*)"
    RE_SENDPKT     = RE_START + r"Sending ([0-9]+) bytes from ([0-9]+) to ([0-9]+): (.*)$"
    RE_ESTABLISHED = RE_START + r"Established channels with ([0-9]+) nodes: (.*)$"
    RE_SIGNATURE   = r"^Signature: (.*)$"
    RE_VERIFIED    = r"^Verified OK$"

    @staticmethod
    def get_content(filename):
        try:
            with open(filename) as f:
                return f.read()
        except e:
            print(f"[-] Error while opening {filename:} {e:}")
            exit(0)

    def __init__(self, filename):
        self._content = LogParser.get_content(filename)
        self.messages = []

        self.parse()

    def parse(self):
        """
        Parse the log file
        """

        for line in self._content.split("\n"):
            msg = None

            if len(line) == 0:
                continue

            if re.search(LogParser.RE_STARTSERVER, line):
                x, ip, port, pubkey = re.findall(LogParser.RE_STARTSERVER, line)[0]
                msg = MessageBuilder.new_message(Message.START_SERVER, x = x, ip = ip, port = port, pubkey = pubkey)
            elif re.search(LogParser.RE_SIGNCMD, line):
                x, payload = re.findall(LogParser.RE_SIGNCMD, line)[0]
                msg = MessageBuilder.new_message(Message.SIGN, x = x, payload = payload)
            elif re.search(LogParser.RE_SENDPKT, line):
                x, size, x_src, x_dst, hexdata = re.findall(LogParser.RE_SENDPKT, line)[0]
                msg = MessageBuilder.new_message(Message.SEND_PACKET, x = x, size = size,
                                                 x_src = x_src, x_dst = x_dst, hexdata = hexdata)
            elif re.search(LogParser.RE_ESTABLISHED, line):
                x, n, nodes = re.findall(LogParser.RE_ESTABLISHED, line)[0]
                msg = MessageBuilder.new_message(Message.CONNECTION, x = x, n = n, nodes = nodes)
            elif re.search(LogParser.RE_SIGNATURE, line):
                signature = re.findall(LogParser.RE_SIGNATURE, line)[0]
                msg = MessageBuilder.new_message(Message.SIGNATURE, signature = signature)
            elif re.search(LogParser.RE_VERIFIED, line):
                pass
            else:
                print(f"Not parsed: {line:}")
                return

            if msg:
                self.messages.append(msg)

        return self.messages

    def get_signature(self, sig_id):
        """
        Get the n-th signature
        """
        for msg in self.messages:
            if isinstance(msg, SignatureMessage):
                if sig_id == 0:
                    return msg
                sig_id -= 1

        return None

    def get_signature_count(self):
        """
        Get the signature count
        """
        count = 0
        for msg in self.messages:
            if isinstance(msg, SignMessage):
                count += 1
        return count

    def get_kr_shares(self, sig_id, peer_id):
        """
        Extract k*r shares from the log file
        """
        sig_id += 1
        share_sent, share_received = [], []
        n = None
        for msg in self.messages:
            # print(msg)
            if sig_id < 0:
                break
            elif sig_id > 0:
                if isinstance(msg, SignMessage):
                    n = len(msg.payload["nodes"])
                    sig_id -= 1
                continue
            else:
                if isinstance(msg, SignMessage):
                    sig_id -= 1
                    continue

                # Here we found the good sig_id
                if not isinstance(msg, SendPacketMessage):
                    continue

                if msg.x_to == peer_id:
                    if len(msg.payload) == 32 and len(share_received) != n - 1:
                        share_received.append(msg)

                if msg.x_from == peer_id:
                    if len(msg.payload) == 32 and len(share_sent) != n - 1:
                        share_sent.append(msg)

        assert len(share_sent) == len(share_received) == n - 1

        return share_sent, share_received

    def get_pb_shares(self, sig_id, peer_id):
        """
        Extract the public point shares from the log file
        """
        sig_id += 1
        share_sent, share_received = [], []
        n = -1
        for msg in self.messages:
            # print(msg)
            if sig_id < 0:
                break
            elif sig_id > 0:
                if isinstance(msg, SignMessage):
                    n = len(msg.payload["nodes"])
                    sig_id -= 1
                continue
            else:
                if isinstance(msg, SignMessage):
                    sig_id -= 1
                    continue

                # Here we found the good sig_id
                if not isinstance(msg, SendPacketMessage):
                    continue

                if msg.x_to == peer_id:
                    if len(msg.payload) == 64 and len(share_received) != n - 1:
                        share_received.append(msg)

                if msg.x_from == peer_id:
                    if len(msg.payload) == 64 and len(share_sent) != n - 1:
                        share_sent.append(msg)

        assert len(share_sent) == len(share_received) == n - 1

        return share_sent, share_received

############################### Challenge related functions ###############################

def recover_kr_product(parser, sig_id, peer_id):
    """
    Recover k*r value using the log file (we use the fact that
    shares S = k_s * r_s + rz_s are transmitted in clear in 
    function smpc_share_revealing_open. 
    """
    share_sent, share_received = parser.get_kr_shares(sig_id, peer_id)

    # Quick sanity check
    assert len(share_received) == len(share_sent)

    shares = []
    for i in range(len(share_sent)):
        shares.append((share_received[i].x_from, int.from_bytes(share_received[i].payload, "big")))
    kr = sss_recover(shares, 0)

    return kr

def recover_pb_share(parser, sig_id, peer_id):
    """
    Recover pb (public nonce) using the log file (we use the fact that
    pb shares are transmitted in clear in function during the smpc_random_keypair. 
    """
    share_sent, share_received = parser.get_pb_shares(sig_id, peer_id)

    # Quick sanity check
    assert len(share_received) == len(share_sent)

    shares = []
    for i in range(len(share_sent)):
        pt_x = int.from_bytes(share_received[i].payload[:32], "big")
        pt_y = int.from_bytes(share_received[i].payload[32:], "big")
        pt_from_other = fastecdsa.point.Point(pt_x, pt_y, SECP256K1_CURVE)
        shares.append((share_received[i].x_from, pt_from_other))

    final_point = fastecdsa.point.Point.IDENTITY_ELEMENT
    for x_i, pt_i in shares:
        term_i = 1
        for x_j, _ in shares:
            if x_i == x_j:
                continue
            inv_ij = modinv((x_j - x_i) % SECP256K1_ORDER, SECP256K1_ORDER)
            term_i = (term_i * x_j * inv_ij) % SECP256K1_ORDER
        final_point += term_i * pt_i
    return final_point

def find_private_key(parser, sig_id, t):
    """
    Find private key
    """
    z = int.from_bytes(hashlib.sha256(DATA_TO_SIGN).digest(), "big")
    public_key = serialization.load_pem_public_key(PUBLIC_KEY_PEM, backend=default_backend())

    sig = parser.get_signature(sig_id)
    r, s = decode_dss_signature(sig.signature)
    pb = recover_pb_share(parser, sig_id, 1)

    # Simple check to ensure the parsing is correct
    assert pb.x == r

    # For all products lengths
    for n_prod in range(1, len(t)):

        # Generate all the possible combination
        for p in combinations(t, n_prod):

            # We compute the candidate private nonce
            k_guess = reduce(lambda x, y: x * y, p)

            tmp = (s * k_guess) % SECP256K1_ORDER
            tmp = (tmp - z) % SECP256K1_ORDER
            secret_key_value = (tmp * modinv(r, SECP256K1_ORDER)) % SECP256K1_ORDER

            secret_key = derive_private_key(secret_key_value, curve=SECP256K1(), backend=default_backend())

            # Compare the public key with the secret key
            if secret_key.public_key().public_numbers() == public_key.public_numbers():
                print(f"[+] Candidate private key: {secret_key_value:}")
                return secret_key_value

    print(f"[-] Private key not found!")
    return -1

def solve(parser):
    """
    Solve function
    Flag: CTF{weak_RNG_strikes_back_again}
    """
    
    sig_count = parser.get_signature_count()
    print(f"[+] Found {sig_count:} signatures inside the log file")

    for sig_id in range(sig_count):
        k_r = recover_kr_product(parser, sig_id, 1)
        print(f"[+] Found k*r : 0x{k_r:032x} (0x{sig_id:02x})")

        t = decompose_prime(k_r)
        print(f"[+] Found prime decomposition for {k_r:}: {t:}")

        priv_key = find_private_key(parser, sig_id, t)
        if priv_key != -1:
            return

def main():
    """
    Main function
    """

    parser = argparse.ArgumentParser(description='SMPC signatures solver')
    parser.add_argument('logfile', metavar='logfile', type=str,
                    help='Log file from the challenge')
    args = parser.parse_args()

    # We start by parsing the messages
    parser = LogParser(args.logfile)
    # messages = parser.parse()

    # Solve the challenge
    solve(parser)

if __name__ == "__main__":
    main()