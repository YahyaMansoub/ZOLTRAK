

---
tags: [crypto, aes, block-cipher]

# AES (Rijndael) — what happens to the plaintext?

AES is a **symmetric block cipher**. It always works on **128-bit blocks** (= **16 bytes**).  
If your message is longer than 16 bytes, you split it into blocks and use a *mode* (CBC/CTR/GCM, etc.).  
Below is **one 16-byte block** going through **AES-128** (10 rounds).

---

## 0) From plaintext bytes → the “State” (4×4 bytes)

Take 16 bytes:

`b0 b1 b2 ... b15`

AES places them into a 4×4 byte matrix called the **State** in **column-major** order:

$$
State =
\begin{bmatrix}
b_0 & b_4 & b_8 & b_{12}\\
b_1 & b_5 & b_9 & b_{13}\\
b_2 & b_6 & b_{10} & b_{14}\\
b_3 & b_7 & b_{11} & b_{15}
\end{bmatrix}
$$

So the *first 4 bytes* fill the **first column**, next 4 fill the **second column**, etc.

---

## 1) Key Expansion → round keys (K0..K10)

AES-128 starts with a **16-byte key**, then expands it into **11 round keys**, each 16 bytes:

- **K0** = used before round 1 (pre-round)
- **K1..K9** = rounds 1..9
- **K10** = final round

**Diagram (key schedule idea):**  
![](https://upload.wikimedia.org/wikipedia/commons/thumb/b/be/AES-Key_Schedule_128-bit_key.svg/960px-AES-Key_Schedule_128-bit_key.svg.png)

---

## 2) Pre-round: AddRoundKey (XOR with K0)

You XOR the state with the round key (byte-by-byte, same positions):

$$
State \leftarrow State \oplus K_0
$$

**Diagram (AddRoundKey):**  
![](https://upload.wikimedia.org/wikipedia/commons/thumb/a/ad/AES-AddRoundKey.svg/771px-AES-AddRoundKey.svg.png)

---

## 3) The “main rounds” (rounds 1..9)

Each round does **four** transformations:

### (a) SubBytes (S-box substitution)
Each byte is replaced using the **AES S-box lookup table** (non-linear step).

**S-box image:**  
![](https://upload.wikimedia.org/wikipedia/commons/f/f1/AES_S-box.png)

### (b) ShiftRows (row shifts)
Row 0: shift left by 0  
Row 1: shift left by 1  
Row 2: shift left by 2  
Row 3: shift left by 3

**Diagram (ShiftRows):**  
![](https://upload.wikimedia.org/wikipedia/commons/thumb/6/66/AES-ShiftRows.svg/960px-AES-ShiftRows.svg.png)

### (c) MixColumns (your “column shuffle”)
Each **column** is mixed by multiplying with a fixed matrix in **GF(2^8)** (byte algebra):

$$
\begin{bmatrix}
b_{0,j}\\ b_{1,j}\\ b_{2,j}\\ b_{3,j}
\end{bmatrix}
=
\begin{bmatrix}
2&3&1&1\\
1&2&3&1\\
1&1&2&3\\
3&1&1&2
\end{bmatrix}
\begin{bmatrix}
a_{0,j}\\ a_{1,j}\\ a_{2,j}\\ a_{3,j}
\end{bmatrix}
\quad (j=0..3)
$$

**Diagram (MixColumns):**  
![](https://upload.wikimedia.org/wikipedia/commons/thumb/7/76/AES-MixColumns.svg/960px-AES-MixColumns.svg.png)

### (d) AddRoundKey (XOR with round key)
$$
State \leftarrow State \oplus K_r
$$

---

## 4) Final round (round 10) — same but NO MixColumns

Final round =

1. SubBytes  
2. ShiftRows  
3. AddRoundKey (with K10)  

**MixColumns is omitted** in the last round.

---

## One-picture overview (round pipeline)

![](https://upload.wikimedia.org/wikipedia/commons/9/96/AES_Encryption_Round.png)

And a compact “round function” view:

![](https://upload.wikimedia.org/wikipedia/commons/thumb/d/d6/Aes_round_function-01.svg/1280px-Aes_round_function-01.svg.png)

---

## Tiny pseudocode (AES-128, 1 block)

- `state = bytes_to_state(plaintext16)`
- `state ^= K0`
- for r = 1..9:
  - `state = SubBytes(state)`
  - `state = ShiftRows(state)`
  - `state = MixColumns(state)`
  - `state ^= Kr`
- final round (r=10):
  - `state = SubBytes(state)`
  - `state = ShiftRows(state)`
  - `state ^= K10`
- `ciphertext16 = state_to_bytes(state)`
