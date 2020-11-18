import json
import requests
import hashlib
from ecpy.curves import Curve,Point

cv = Curve.get_curve('secp256k1')
G = Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8, 
    cv
)

def H(R, m):
    h = hashlib.sha256()
    h.update((R.x).to_bytes(32, 'big'))
    h.update((R.y).to_bytes(32, 'big'))
    h.update(m)
    return int.from_bytes(h.digest(), 'big')

def get_aggregated():
    """
    Request the server to get the aggregated public key
    """
    url = 'http://multisig.donjon-ctf.io:6000'
    info = json.loads(requests.get(url).content)

    aggregated_str = info["Aggregated public key"]
    x = int(aggregated_str[:64], 16)
    y = int(aggregated_str[64:], 16)
    aggregated_real = Point(x, y, cv)

    return aggregated_real

def solve():
    """
    Solve function

    Solution of this challenge is almost given here:
    # https://blockstream.com/2018/01/23/en-musig-key-aggregation-schnorr-signatures/

    Flag: CTF{Multi_means_several_right?}
    """
    url = 'http://multisig.donjon-ctf.io:6000'
    cmd = dict()

    aggregated = get_aggregated()

    priv_key = 4
    pub_key  = priv_key * G

    fake_pub_key = pub_key - aggregated

    r = 4 # Random issued from the PS3 RNG ;)
    R = 4 * G
    cmd["public_nonce"] = f"{R.x:064x}{R.y:064x}"
    cmd["public_key"] = f"{fake_pub_key.x:064x}{fake_pub_key.y:064x}"

    sig = (r - H(R, b"We lost. Dissolving group now.") * priv_key) % 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

    cmd["signature"] = f"{sig:064x}"

    x = requests.post(url, json = cmd)
    t = json.loads(x.text)

    print(f"[+] Found flag: {t['message']:}")

if __name__ == "__main__":
    solve()