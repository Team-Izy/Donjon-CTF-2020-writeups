import numpy as np
import h5py
from sage.all import GF, ZZ, vector, Matrix
from sage.modules.free_module_integer import IntegerLattice

from ecpy.curves     import Curve,Point
from Crypto.Cipher import AES
import sys


# CURVE
cv = Curve.get_curve('secp256k1')
n = cv.order
p = cv.field

def inv(x,n):
    return pow(x, n-2, n)


def bits_tuple_to_int(t):
    x = 0
    for bit in t:
        x <<= 1
        x += bit
    return x

def attack(u,t,l):
    ########## u vector ##############
    d = len(u)
    uv = [(1<<(l[i]+1)) * u[i] for i in range(d)] + [0]

    ######### B_hat matrix ##########
    B_hat = [ [0] * i + [(1<<(l[i]+1))*n] + [0]*(d-i) + [0] for i in range(d)]
    B_hat.append([(1<<(l[i]+1))*t[i] for i in range(d)]+[1] + [0])
    B_hat.append(uv + [n])

    B_hat = Matrix(ZZ, B_hat)


    ######## Solve SVP for B_hat with LLL #####
    L = IntegerLattice(B_hat, lll_reduce=False)
    lll = L.LLL()

    # According to the article, the reduced latice should contain (y, -n)
    # where y = (.,., ..., private_key)

    pk_candidates = []
    for i in range(d+2):
        if lll[i][d+1] == -n:
            pk_candidates.append(lll[i][d])


    # Decrypt flag with potential private keys
    ENCRYPTED_FLAG = b'u\xcb\xea\x01\xaapuj\xc3\x90\xe4O\xb8\xbf\xd8\x87\xd3\x86\xd2\xd8\x11\xf3\x03S\x07\x8b\xc6Q\\\xa0\xd4\xd3\x83\tx#7L\x03\xf5=CO\x90*}u['
    print(f"{len(pk_candidates)} candidates for private key found")
    for pk in pk_candidates:
        pk= int(pk %n)
        key = pk.to_bytes(32,"big")
        cipher = AES.new(key,AES.MODE_ECB)
        flag = cipher.decrypt(ENCRYPTED_FLAG)
        if flag.lower().startswith(b"ctf"):
            return flag
    print("\tbut no key found...")
    return None
def main():

    ########### Get signatures ############
    f = h5py.File('./all_signatures.h5', 'r')

    #print(list(f.keys()))
    leakages = f['leakages']
    values = f['values']


    ########### Get leaks (ci,li) = (LSB bits leaked big endian, number of bits leaked) ############
    leaks = list()
    with open("100000_nonce_partial_leaks.txt") as f:
        for line in f:
            ci = eval(line.strip())
            li = len(ci)
            leaks.append((ci, li))

    ############ Compute (ti,ui) for leaks with li >= 6 #########
    u = list()
    c = list()
    l = list()
    t = list()
    a = list()
    r = list()
    s = list()
    for i, val in enumerate(values):
        if leaks[i][1] <= 5:
            continue
        h, ri, si, _, _ = val
        h = int(bytes(h.tolist()).hex(), 16)
        ri = int(bytes(ri.tolist()).hex(), 16)
        r.append(ri)
        si = int(bytes(si.tolist()).hex(), 16)
        s.append(s)
        ci, li = leaks[i]
        ci = bits_tuple_to_int(ci)
        c.append(ci)
        l.append(li)
        ai = (ci - n) % (1<<li)
        a.append(ai)
        ti = (ri * inv((1<<li)*si, n)) % n
        t.append(ti)
        ui = (((ai - h * inv(si, n)) * inv(1<<li, n))%n + n*inv(1<<(li+1), n) ) % n
        u.append(ui)

    import random
    sample_size = 256 // 6
    nb_tries = 0
    while True:
        print(f"############# RANDOM BATCH of size {sample_size} ############## ")
        indices = random.sample(range(len(u)), sample_size)
        u_i, t_i, l_i = list(), list(), list()
        for i in indices:
            u_i.append(u[i])
            t_i.append(t[i])
            l_i.append(l[i])
        flag = attack(u_i, t_i, l_i)
        if flag is not None:
            print(f"FLAG is : {flag}")
            break
        nb_tries += 1
        if nb_tries == 5:
            nb_tries = 0
            sample_size += 5
        print()

if __name__ == '__main__':
    main()
