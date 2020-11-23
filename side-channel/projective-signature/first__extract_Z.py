#!/usr/bin/python3

import h5py
import numpy as np
from matplotlib import pyplot as plt


def inv_gcd_from_trace(trace):
    a = 0
    b = 1
    for ch in trace[::-1]:
        if ch == "A":
            a = (a * 2) + b
            a, b = b, a
        elif ch == "B":
            a = (a * 2) + b
        elif ch == "C":
            a *= 2
        else:
            assert False
    return a


f = h5py.File('all_signatures.h5', 'r')
leakages = f['leakages']
values = f['values']

v0,v1,v2,v3 = 49, 89, 129, 169
v0,v1,v2,v3 = range(1,5)
pattern_A = np.array([v2]*4 + [v0] + [v1]*2 + [v2]*4 + [v3]*10, dtype=np.uint8)
pattern_B = np.array([v2]*4 +        [v1]*2 + [v2]*4 + [v3]*10, dtype=np.uint8)
pattern_C = np.array(                [v1]*2 +          [v3]*10, dtype=np.uint8)
pattern_stop = np.array([v0]*20)

def extract_Z():
    N = 50
    Z_list = list()
    for (i, leak) in enumerate(leakages):
        if i & 0xFF == 0:
            print(f"{str(i*100//100000).zfill(3)}%", end='\r')
        conv = np.convolve(leak, np.ones((N,))/N, mode='valid')
        start = np.where(conv < 50.0)[0][0]
        leak = np.roll(leak, -start)
        while leak[N]<70.0:
            leak = np.roll(leak, -1)
        leak = np.roll(leak, -N)
        v0_indices = np.where(leak < 68)
        v0v1_indices = np.where(leak < 108)
        v0v1v2_indices = np.where(leak < 148)
        leak[:] = v3
        leak[v0v1v2_indices] = v2
        leak[v0v1_indices] = v1
        leak[v0_indices] = v0
        t = 0
        s=""
        while True:
            for (letter,pattern) in zip("ABC", [pattern_A, pattern_B, pattern_C]):
                if np.array_equal(leak[t:t+len(pattern)], pattern):
                    t += len(pattern)
                    s += letter
                    break
            else:
                assert np.array_equal(leak[t:t+len(pattern_stop)], pattern_stop)
                break
        Z_list.append(inv_gcd_from_trace(s))
    print(Z_list)
    Z_list = np.array(Z_list)
    np.save("Z.npy", Z_list)

def export_Z():
    Z0_l = np.load("Z.npy", allow_pickle=True)
    Z_and_points = list()
    for i in range(len(Z0_l)):
        v = values[i]
        Px = int(bytes(v["Px"].tolist()).hex(), 16)
        Py = int(bytes(v["Py"].tolist()).hex(), 16)
        h = int(bytes(v["digest"].tolist()).hex(), 16)
        r = int(bytes(v["ECDSA_r"].tolist()).hex(), 16)
        s = int(bytes(v["ECDSA_s"].tolist()).hex(), 16)
        Z_and_points.append(dict(Z=Z0_l[i], P=(Px,Py), h=h, r=r, s=s))
    with open("Z_and_points.dict", "w") as f:
        f.write(Z_and_points)

if __name__ == "__main__":
    extract_Z()
    export_Z()
