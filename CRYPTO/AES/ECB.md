
---


---
tags: [crypto, aes, ecb, ctf, chosen-plaintext]
---

# AES-ECB (Electronic Codebook) + the classic “append-the-flag” oracle attack

This writeup is for the CTF-style oracle:

- you send: `your_input`
- the server builds: `your_input || FLAG`
- it encrypts that whole thing with **AES-ECB** under a fixed secret key
- it returns the ciphertext

Goal: recover `FLAG` without knowing the key.

---

## 1) What AES-ECB does (and why it’s weak)

AES is a **block cipher** with **16-byte (128-bit) blocks**.

**ECB mode** means:
- split plaintext into 16-byte blocks
- encrypt each block *independently* with the same key
- no IV, no chaining, no randomness

So ECB is **deterministic**:
- same 16-byte plaintext block (under same key) → same 16-byte ciphertext block

That single property is what makes the oracle attack possible.

### Visual intuition
ECB encrypts blocks in parallel, independently:

![](https://upload.wikimedia.org/wikipedia/commons/thumb/d/d6/ECB_encryption.svg/1280px-ECB_encryption.svg.png)

And why people say “ECB leaks patterns” (the famous ECB “penguin”):

![](https://upload.wikimedia.org/wikipedia/commons/c/c0/Tux_ECB.png)

---

## 2) The oracle we’re attacking

Typical oracle logic (conceptually):

```text
oracle(input):
    msg = input || FLAG
    msg = PKCS#7_pad(msg, 16)
    return AES_ECB_encrypt(key, msg)
````

Important details:

- the key is constant across calls
    
- the FLAG is constant across calls
    
- you control the prefix (`input`) fully
    

---

## 3) Why the attack works (core idea)

Because ECB is deterministic, if you can force the oracle to encrypt a block you fully control, you can build a “dictionary”:

- pick a block of plaintext
    
- ask the oracle for the ciphertext block
    
- repeat for all 256 possibilities of the next unknown byte
    
- match ciphertext blocks → reveal the byte
    

This is called **byte-at-a-time ECB decryption**.

---

## 4) Attack walkthrough (byte-at-a-time)

### Step A — Find the block size (you expect 16, but verify)

Send inputs of increasing length:

- input = `""` → ciphertext length = L
    
- input = `"A"` → ciphertext length = maybe L
    
- keep adding bytes until ciphertext length jumps by a fixed amount
    

That jump size is the block size (almost always 16 for AES).

**Practical check:** measure ciphertext length in bytes (or decode hex/base64 first).

---

### Step B — Confirm it’s ECB

Send an input that contains repeated identical blocks, like:

- `"A" * (16 * 4)`
    

If you see repeated ciphertext blocks (exact repeats), it’s ECB.

---

### Step C — Recover the flag one byte at a time

Let `B = 16`.

You want to reveal `FLAG[0]`, then `FLAG[1]`, etc.

**Trick:** choose padding so the next unknown flag byte lands at the end of a block.

For byte index `i` (0-based):

- `pad_len = (B - 1) - (i % B)`
    
- `pad = "A" * pad_len`
    

When you query `oracle(pad)`, the plaintext looks like:

```text
[ AAAAA....AAAA ][ known_flag_bytes_so_far + next_unknown_byte ][ rest... ]
         ^ this block ends with the next byte you want
```

Now do this:

1. **Get the target ciphertext block**
    

- `C = oracle(pad)`
    
- `block_index = i // B`
    
- `target = C[block_index]` (the block you’re attacking)
    

2. **Build a dictionary for that block**  
    You craft inputs of length exactly one block where the last byte varies:
    

- `probe = pad || known || x`
    

Where:

- `known` = the bytes of the flag you already recovered
    
- but only the last `(B - 1)` bytes matter for the current block
    
- `x` = candidate byte from 0..255
    

For each `x`:

- `C2 = oracle(probe)`
    
- `candidate_block = C2[block_index]`
    
- store: `candidate_block → x`
    

3. **Match**
    

- Look up `target` in the dictionary.
    
- The matching `x` is the correct next flag byte.
    

4. **Repeat**  
    Increment `i` and keep going until you recover the full flag.
    

---

## 5) When do you stop?

Eventually you’ll recover into padding (because the oracle pads before encrypting).  
Common CTF approach:

- keep recovering bytes until it “looks like a flag” and/or
    
- detect valid PKCS#7 padding at the end and strip it
    

---

## 6) Common gotchas in real CTF services

- **Ciphertext encoding:** returned as hex/base64; decode before slicing into 16-byte blocks.
    
- **Newlines / input parsing:** the service may add `\n` or strip it; be consistent.
    
- **Unknown fixed prefix:** if the server prepends random bytes before your input, this becomes the “harder” variant (you must first align to a block boundary).
    
- **Rate limits:** dictionary is 256 queries per byte; optimize by reusing connections / batching.
    

---

## 7) Why this is a “mode misuse” problem (not “AES is broken”)

AES is fine. The issue is:

- ECB leaks equality of blocks
    
- the oracle gives you chosen-plaintext access to `input || secret`
    

**Fixes (high level):**

- never use ECB for real data
    
- use AEAD modes like **GCM** or **ChaCha20-Poly1305**
    
- don’t encrypt attacker-controlled data concatenated with secrets
    
- add randomness (IV/nonce) correctly (ECB has none)
    

```

Sources (for your references, not needed in the note): ECB determinism / definition is specified in NIST SP 800-38A. :contentReference[oaicite:0]{index=0} The “byte-at-a-time ECB decryption” oracle pattern is the standard Cryptopals challenge. :contentReference[oaicite:1]{index=1} A concise explanation of why the chosen-plaintext oracle breaks the appended secret relies on ECB’s equal-block → equal-ciphertext property. :contentReference[oaicite:2]{index=2}
::contentReference[oaicite:3]{index=3}
```