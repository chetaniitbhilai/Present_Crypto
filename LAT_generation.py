sbox = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]  # sbox

bits = 4    # number of bits of input to sbox
size = 2**bits

# Linear Approximation Table (LAT)
LAT = [[0] * size for _ in range(size)]

for alpha in range(size):
    for beta in range(size):
        equal = 0  # Counter for matching alpha.m and beta.S[m]

        # Iterate through all possible plaintexts
        for m in range(2**bits):
            mask_alpha_m = bin(alpha & m).count('1') % 2    # alpha.m
            mask_beta_c = bin(beta & sbox[m]).count('1') % 2    # beta.S[m]

            # Check if they are equal
            if mask_alpha_m == mask_beta_c:
                equal += 1

        LAT[alpha][beta] = equal - 8  # Update LAT with the difference

# Remove the first row (alpha = 0) and first column (beta = 0)
LAT = [row[1:] for row in LAT[1:]]

# Print the resulting LAT
for row in LAT:
    print(row)
