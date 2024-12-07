def initialize_sbox():
    """Initialize the S-box."""
    return [
        [0, 12],
        [1, 5],
        [2, 6],
        [3, 11],
        [4, 9],
        [5, 0],
        [6, 10],
        [7, 13],
        [8, 3],
        [9, 14],
        [10, 15],
        [11, 8],
        [12, 4],
        [13, 7],
        [14, 1],
        [15, 2]
    ]

def compute_ddt(sbox, bits):
    """
    Compute the Difference Distribution Table (DDT) for a given S-box.
    
    Args:
        sbox (list): The substitution box.
        bits (int): Number of bits for the S-box input/output.
    
    Returns:
        list: The computed DDT as a list of lists.
    """
    input_diff = range(2**bits)
    ddt = []

    # Compute the DDT row by row
    for diff in input_diff:
        freq = {}
        for u0 in range(2**bits):
            u1 = u0 ^ diff
            v0, v1 = sbox[u0][1], sbox[u1][1]
            output_diff = v0 ^ v1
            freq[output_diff] = freq.get(output_diff, 0) + 1

        # Create a row of the DDT
        ddt_row = [freq.get(i, 0) for i in range(2**bits)]
        ddt.append(ddt_row)

    return ddt

def display_ddt(ddt):
    """
    Display the DDT in a formatted way.
    
    Args:
        ddt (list): The DDT to display.
    """
    for row in ddt:
        print('  '.join(str(val) if val != 0 else '-' for val in row))

# Main execution
if __name__ == "__main__":
    # Initialize S-box
    sbox = initialize_sbox()

    # Compute the DDT for the given S-box and 4-bit input/output
    bits = 4
    ddt = compute_ddt(sbox, bits)

    # Display the computed DDT
    print("Difference Distribution Table (DDT):")
    display_ddt(ddt)
