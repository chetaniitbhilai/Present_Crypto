import random
import os

class PresentCipher:
    """
    Implements the Present cipher with key scheduling, encryption, 
    and differential cryptanalysis methods.
    """

    def __init__(self):
        # S-box for substitution
        self.sbox = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]

        # Permutation layer positions
        self.permute = [0] * 64
        self._init_permutation_layer()

        # Cipher configurations
        self.rounds = 32
        self.masterKey = 0
        self.subkeys = []

        # Cipher state variables
        self.possibleAfterSbox = []
        self.possibleCipherText = []
        self.m = 0

    def set_key(self, key):
        """Sets the master key and generates round subkeys."""
        key_bits = len(key) * 4
        if key_bits == 80 or key_bits == 128:
            self.masterKey = int.from_bytes(bytes.fromhex(key), byteorder='big')
            if key_bits == 80:
                self._generate_subkeys_80()
            else:
                self._generate_subkeys_128()
        else:
            raise ValueError("Key length must be 80 bits or 128 bits.")

    def set_message(self, message):
        """Sets the plaintext message, applying padding if necessary."""
        if len(message) * 8 > 64:
            raise ValueError("Message length must be 64 bits or less.")
        pad_count = (8 - len(message) % 8) % 8
        message += chr(pad_count) * pad_count
        self.m = int.from_bytes(message.encode(), byteorder='big')

    def set_message_as_int(self, int_message):
        """Sets the plaintext message as an integer."""
        self.m = int_message

    def _init_permutation_layer(self):
        """Initializes the permutation layer."""
        for i in range(64):
            self.permute[i] = (16 * i) % 64 + i // 4

    def _generate_subkeys_80(self):
        """Generates subkeys for an 80-bit master key."""
        for i in range(1, self.rounds + 1):
            self.subkeys.append(self.masterKey >> 16)
            self.masterKey = ((self.masterKey & (2**19 - 1)) << 61) | (self.masterKey >> 19)
            self.masterKey = ((self.sbox[self.masterKey >> 76] << 76) | self.masterKey & (2**76 - 1))
            self.masterKey ^= i << 15

    def _generate_subkeys_128(self):
        """Generates subkeys for a 128-bit master key."""
        for i in range(1, self.rounds + 1):
            self.subkeys.append(self.masterKey >> 64)
            self.masterKey = ((self.masterKey & (2**67 - 1)) << 61) | (self.masterKey >> 67)
            upper_bits = ((self.sbox[self.masterKey >> 124] << 124) |
                          (self.sbox[(self.masterKey >> 120) & 15] << 120))
            self.masterKey = upper_bits | (self.masterKey & (2**120 - 1))
            self.masterKey ^= i << 62

    def _apply_permutation_layer(self, state):
        """Applies the permutation layer to the given state."""
        return sum(((state >> i) & 1) << self.permute[i] for i in range(64))

    def _add_round_key(self, state, subkey):
        """Applies the round key."""
        return state ^ subkey

    def _apply_sbox_layer(self, state):
        """Applies the S-box substitution layer."""
        return sum(self.sbox[(state >> (i * 4)) & 0xF] << (i * 4) for i in range(16))

    def _reverse_sbox(self, nibble):
        """Finds the inverse S-box value for a given nibble."""
        return self.sbox.index(nibble)

    def encrypt(self):
        """Encrypts the current message using the Present cipher."""
        state = self.m
        for i in range(self.rounds - 1):
            state = self._add_round_key(state, self.subkeys[i])
            state = self._apply_sbox_layer(state)
            state = self._apply_permutation_layer(state)
        state = self._add_round_key(state, self.subkeys[-1])
        return hex(state).replace('0x', '')

    def three_round_encrypt(self, message):
        """Encrypts the message for the first three rounds."""
        state = message
        for i in range(3):
            state = self._add_round_key(state, self.subkeys[i])
            state = self._apply_sbox_layer(state)
            if i < 2:
                state = self._apply_permutation_layer(state)
        return state

    def generate_message_pairs(self, exponent, diff):
        """Generates plaintext pairs based on a given difference."""
        self._filter_possible_sbox_outputs()
        count = 2**exponent
        valid_pairs = 0
        for i in range(count):
            m1, m2 = i, i ^ diff
            c1, c2 = self.three_round_encrypt(m1), self.three_round_encrypt(m2)
            if any(c1 ^ c2 == val for val in self.possibleAfterSbox):
                self.possibleCipherText.append(m1)
                valid_pairs += 1
        print(f"Filtered: {valid_pairs} Pairs")

    def guess_key(self, diff):
        """Performs key guessing based on differential analysis."""
        print("Possible Keys:")
        for guess in range(64):
            key = f"0x0{guess:02x}"  # Generate key guess
            key_int = int(key, 16)
            counter = 0
            for m1 in self.possibleCipherText:
                m2 = m1 ^ diff
                c1, c2 = self.three_round_encrypt(m1), self.three_round_encrypt(m2)
                c1_prime, c2_prime = c1 ^ key_int, c2 ^ key_int
                # Extract S-box inputs
                s0_c1 = ((c1_prime >> 48) & 0xF)
                s0_c2 = ((c2_prime >> 48) & 0xF)
                s8_c1 = ((c1_prime >> 56) & 0xF)
                s8_c2 = ((c2_prime >> 56) & 0xF)
                # Reverse S-box
                if (self._reverse_sbox(s0_c1) ^ self._reverse_sbox(s0_c2) == 9 and
                        self._reverse_sbox(s8_c1) ^ self._reverse_sbox(s8_c2) == 9):
                    counter += 1
            if counter >= 1024:
                print(key, counter / 2**18)
        print("Actual Subkey for last round:", hex(self.subkeys[2]))

    def _filter_possible_sbox_outputs(self):
        """Filters possible outputs of the S-box after applying the permutation layer."""
        self.possibleAfterSbox = [
            self._apply_permutation_layer(int(f"0x0000000{s1}0000000{s2}", 16))
            for s1 in "2468ce" for s2 in "2468ce"
        ]


def main():
    cipher = PresentCipher()
    key = os.urandom(10)
    print("Master Key ->", key.hex())
    cipher.set_key(key.hex())
    cipher.generate_message_pairs(18, 16388)
    cipher.guess_key(16388)

if __name__ == "__main__":
    main()
