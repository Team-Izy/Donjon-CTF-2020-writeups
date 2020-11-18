# -*- coding: utf-8 -*-

from pwn import remote
from base64 import b64decode, b64encode
from struct import unpack_from, pack

############################ Server communication ############################

class Remote:
    """
    Simple class to communicate with the server
    """

    URL  = "ots-sig.donjon-ctf.io"
    PORT = 4001

    def __init__(self):
        self._p = remote(Remote.URL, REMOTE.PORT)

    def read_random(self):
        self._p.recvuntil("signature:")

        buf = bytes()
        for _ in range(7):
            self._p.sendline()
            pk = self._p.recvuntil("signature:")[30: ].split(b"\n")[0]
            buf += b64decode(pk)
        
        # print(len(buf))

        # Quick sanity check
        assert len(buf) % 7 == 0

        k = 0
        while k < len(buf) // 8:
            r = unpack_from("<Q", buf, 7 * k)[0]
            yield r
            k += 1

    def send_response(self, sig):
        self._p.interactive()

############################ PRNG stuff ############################

class PRNG:
    """
    Simple PRNG class
    """

    LENGTH = 607
    TAP    = 273

    def __init__(self):
        """
        Init the PRNG
        """
        self._state = [ 0 ] * PRNG.LENGTH
        self._tap   = 0
        self._feed  = PRNG.LENGTH - PRNG.TAP

    def populate(self, val):
        """
        Populate PRNG
        """
        self._feed = (self._feed - 1) % PRNG.LENGTH
        self._tap  = (self._tap  - 1) % PRNG.LENGTH

        if val < 0:
            val += 2 ** 64

        self._state[self._feed] = val

    def random(self):
        """
        Generate a random
        """
        self._feed = (self._feed - 1) % PRNG.LENGTH
        self._tap  = (self._tap  - 1) % PRNG.LENGTH

        r = (self._state[self._feed] + self._state[self._tap]) % (2**64)
        self._state[self._feed] = r
        return r

def solve():
    """
    Flag: CTF{m4th_RanD_1s_s0_pr3d1cT4bl3}
    """
    prng = PRNG()
    remote = Remote()

    # We look at least PRNG.LENGTH random in order to 
    # be synchronize our state with the server's one
    g = remote.read_random()
    for i in range(PRNG.LENGTH + 30):
        val = g.__next__()
        prng.populate(val)

    # Ugly loop to empty the random buffer
    while True:
        try:
            v_1 = g.__next__()
            v_2 = prng.random()
        except:
            break

    for _ in range(136):
        prng.random()

    privkey = bytes()
    i = 0
    while len(privkey) < 1088:
        # Here we generate a random stream in the same way this is done in the 
        # Go implementation. Since the PRNG only produces 63-bits values, we drop
        # the most significant byte (see: https://golang.org/src/math/rand/rand.go).
        r = prng.random()
        privkey += pack("<Q", r)[:7]
        i += 1

    print("[+] Private key found:", b64encode(privkey[:1088]))

    remote.send_response("test")

def main():
    """
    Main function
    """
    solve()

if __name__ == '__main__':
    main()
