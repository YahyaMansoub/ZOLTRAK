import requests

BASE = "https://aes.cryptohack.org/ecb_oracle"
BLOCK = 16

def oracle_encrypt(pt: bytes) -> bytes:
    pt_hex = pt.hex()
    url = f"{BASE}/encrypt/{pt_hex}/"
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    return bytes.fromhex(r.json()["ciphertext"])

def get_block(ct: bytes, idx: int) -> bytes:
    return ct[idx*BLOCK:(idx+1)*BLOCK]

def recover_flag(known_start=b"crypto{", stop=b"}", max_len=200) -> bytes:
    known = bytearray(known_start)

    while len(known) < max_len and known[-1:] != stop:
        k = len(known)

        pad_len = BLOCK - 1 - (k % BLOCK)
        if pad_len == 0:          # avoid empty request
            pad_len = BLOCK
        pad = b"A" * pad_len

        # where the next unknown byte lands (index counted from start of pad||FLAG)
        block_idx = (pad_len + k) // BLOCK

        target = get_block(oracle_encrypt(pad), block_idx)

        found = None
        for b in range(256):
            ct = oracle_encrypt(pad + bytes(known) + bytes([b]))
            if get_block(ct, block_idx) == target:
                found = b
                break

        if found is None:
            raise ValueError("No matching byte found")

        known.append(found)
        print(bytes(known))

    return bytes(known)

if __name__ == "__main__":
    # resume from your last output:
    flag = recover_flag(b"crypto{p3n6u1n5")
    print("FLAG =", flag.decode(errors="replace"))
 