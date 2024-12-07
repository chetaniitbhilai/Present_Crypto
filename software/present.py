# present.py

SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
SBOX_INV = [0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA]
PBOX = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51, 4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55, 8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59, 12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63]
PBOX_INV = [PBOX.index(x) for x in range(64)]

def sbox_layer(state): return sum((SBOX[(state >> (4 * i)) & 0xF] << (4 * i)) for i in range(16))
def sbox_layer_inv(state): return sum((SBOX_INV[(state >> (4 * i)) & 0xF] << (4 * i)) for i in range(16))
def pbox_layer(state): return sum(((state >> i) & 1) << PBOX[i] for i in range(64))
def pbox_layer_inv(state): return sum(((state >> i) & 1) << PBOX_INV[i] for i in range(64))
def add_round_key(state, round_key): return state ^ round_key

def key_schedule(key, rounds=32):
    round_keys = []
    for round_number in range(1, rounds + 1):
        round_keys.append(key >> 16)
        key = ((key & 0xFFFFFFFFFFFFFFFFFFFFFFFF) << 61 | (key >> 19)) & (2**80 - 1)
        key = (SBOX[key >> 76] << 76) | (key & (2**76 - 1))
        key ^= round_number << 15
    return round_keys

def present_encrypt(plaintext, key, rounds=32):
    round_keys = key_schedule(key, rounds)
    state = plaintext
    for round_key in round_keys[:-1]:
        state = add_round_key(state, round_key)
        state = sbox_layer(state)
        state = pbox_layer(state)
    return add_round_key(state, round_keys[-1])

def present_decrypt(ciphertext, key, rounds=32):
    round_keys = key_schedule(key, rounds)
    state = ciphertext
    state = add_round_key(state, round_keys[-1])
    for round_key in reversed(round_keys[:-1]):
        state = pbox_layer_inv(state)
        state = sbox_layer_inv(state)
        state = add_round_key(state, round_key)
    return state
