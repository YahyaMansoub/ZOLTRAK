


---

## tags: [crypto, aes, cbc, ctf, bit-flipping, malleability]

# AES-CBC mode + the classic CBC bit-flipping cookie attack

AES is a block cipher that works on fixed-size blocks of **16 bytes (128 bits)**. To encrypt longer messages, you use a _mode of operation_. **CBC (Cipher Block Chaining)** is one of the older modes.

This note explains:

1. how AES-CBC encryption/decryption works
    
2. why CBC is _malleable_ (you can tamper with ciphertext to predictably change decrypted plaintext)
    
3. how that malleability becomes a practical attack when a server checks something like `admin=True` after decrypting your cookie
    

---

## 1) CBC: structure and intuition

CBC splits plaintext into 16-byte blocks:

- plaintext blocks: $P_1, P_2, \dots, P_n$
    
- ciphertext blocks: $C_1, C_2, \dots, C_n$
    
- and a random 16-byte **IV** (Initialization Vector): $IV$
    

### CBC encryption

CBC “chains” blocks so each plaintext block is XORed with the previous ciphertext block before encryption.

For block 1:

$$  
C_1 = E_K(P_1 \oplus IV)  
$$

For later blocks:

$$  
C_i = E_K(P_i \oplus C_{i-1}) \quad \text{for } i \ge 2  
$$

### CBC decryption

Decryption reverses that process:

For block 1:

$$  
P_1 = D_K(C_1) \oplus IV  
$$

For later blocks:

$$  
P_i = D_K(C_i) \oplus C_{i-1} \quad \text{for } i \ge 2  
$$

### Visual (CBC diagram)

![](https://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/1280px-CBC_encryption.svg.png)

![](https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/1280px-CBC_decryption.svg.png)

(ECB treats blocks independently; CBC links them through XOR, which is why CBC avoids ECB’s “pattern leakage”.)

---

## 2) Important property: CBC is malleable

“Malleable” means: an attacker can modify ciphertext (or IV) to cause predictable changes in the decrypted plaintext _without knowing the key_.

Look at decryption:

$$  
P_1 = D_K(C_1) \oplus IV  
$$

If an attacker changes the IV to $IV'$, the new first plaintext block becomes:

$$  
P_1' = D_K(C_1) \oplus IV'  
$$

XOR the two equations:

$$  
P_1' \oplus P_1 = IV' \oplus IV  
$$

So: **any bit flips you apply to the IV flip the same bits in the decrypted $P_1$.**

Similarly for later blocks:

$$  
P_i = D_K(C_i) \oplus C_{i-1}  
$$

If you change $C_{i-1}$ to $C_{i-1}'$:

$$  
P_i' \oplus P_i = C_{i-1}' \oplus C_{i-1}  
$$

So: **flipping bits in $C_{i-1}$ flips bits in $P_i$.**

Key idea: CBC gives confidentiality, but not integrity.  
If there is no MAC / AEAD tag, the receiver can’t tell the ciphertext was tampered with.

---

## 3) The cookie challenge logic

The server issues an encrypted cookie like:

`admin=False;expiry=<timestamp>`

Then later it decrypts your submitted ciphertext and checks if `admin=True` appears as a token.

Typical code (conceptually):

- issue:
    
    - choose random IV
        
    - encrypt with AES-CBC
        
    - return: `IV || C1 || C2 || ...` (often hex encoded)
        
- verify:
    
    - take (ciphertext, iv)
        
    - decrypt AES-CBC
        
    - unpad
        
    - split by `;`
        
    - if one field equals `admin=True` → return flag
        

This is vulnerable because you can change the decrypted value of `admin=False` to `admin=True` by changing the IV (since that string is in the first plaintext block).

---

## 4) CBC bit-flipping attack (general method)

### Goal

Change a known plaintext fragment in the first block:

`admin=False;...`

into:

`admin=True;...`

But you don’t know the key, so you can’t recompute a valid CBC ciphertext.  
Instead, you exploit:

$$  
P_1 = D_K(C_1) \oplus IV  
$$

### Byte-level rule

At some byte position $j$ in block 1:

- original byte: $p_j$
    
- desired byte: $p_j'$
    

Choose:

$$  
\Delta_j = p_j \oplus p_j'  
$$

Then modify the IV byte:

$$  
IV_j' = IV_j \oplus \Delta_j  
$$

Because:

$$  
P_{1,j}' = (D_K(C_1))_j \oplus IV_j' = (D_K(C_1))_j \oplus (IV_j \oplus \Delta_j) = P_{1,j} \oplus \Delta_j = p_j'  
$$

That’s the entire attack.

### Why we often change `False` → `True;`

`False` is 5 bytes. `True;` is also 5 bytes.  
Same length means you can swap without shifting the rest of the cookie.

Also, if the server checks tokens split by `;`, making:

`admin=True;;expiry=...`

is fine because splitting yields a clean token `admin=True`.

---

## 5) The exact attack we just did (with your cookie)

Your cookie returned as hex:

`1d2e3932272b5c99d05d28efdda3499b 51dfa27a28e264802f6c457c082726f2 390b1d374fcd43210b6656e3bb143e92`

Split into 16-byte blocks (32 hex chars each):

- $IV$ = `1d2e3932272b5c99d05d28efdda3499b`
    
- $C_1$ = `51dfa27a28e264802f6c457c082726f2`
    
- $C_2$ = `390b1d374fcd43210b6656e3bb143e92`
    

We assume the plaintext begins with ASCII:

`admin=False;...`

The substring `False` starts at byte offset 6 (0-based) in:

`a d m i n = F a l s e ...`

So we target positions 6..10 in the first block.

We want:

`False` → `True;`

Compute XOR deltas per byte:

- `F` → `T` gives delta `0x12`
    
- `a` → `r` gives delta `0x13`
    
- `l` → `u` gives delta `0x19`
    
- `s` → `e` gives delta `0x16`
    
- `e` → `;` gives delta `0x5e`
    

So we XOR these into the IV at offsets 6..10.

Original IV bytes (offsets 6..10):

- `5c 99 d0 5d 28`
    

New IV bytes:

- `5c^12 = 4e`
    
- `99^13 = 8a`
    
- `d0^19 = c9`
    
- `5d^16 = 4b`
    
- `28^5e = 76`
    

So the modified IV becomes:

$IV'$ = `1d2e3932272b4e8ac94b76efdda3499b`

Then you send to the checker:

- `cookie = C1||C2 = 51dfa27a28e264802f6c457c082726f2390b1d374fcd43210b6656e3bb143e92`
    
- `iv = IV' = 1d2e3932272b4e8ac94b76efdda3499b`
    

The server decrypts and sees a token `admin=True`, so it returns the flag.

---

## 6) Why this is a real-world security issue

CBC encryption alone provides confidentiality, but NOT integrity.

If you decrypt attacker-controlled ciphertext and then _trust the plaintext_, you are exposed to malleability attacks like this.

### How to fix it properly

- Use an AEAD mode (recommended): **AES-GCM**, **ChaCha20-Poly1305**
    
- Or “Encrypt-then-MAC”: compute a MAC over `(IV || ciphertext)` and verify it before decrypting
    
- Never treat decrypted data as trustworthy without authentication
    

---

## 7) Quick mental checklist for spotting CBC bit-flip challenges

If you see:

- AES-CBC encryption of user-visible structured text (cookies, tokens, `key=value;key=value`)
    
- the ciphertext + IV is given to the client
    
- the server decrypts it and checks for a privileged field
    
- no MAC / AEAD tag
    

Then you should immediately think:  
**CBC bit-flipping attack** (malleability exploit).