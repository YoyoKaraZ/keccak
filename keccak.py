import sys

sha3_rates = {
    224: 1152,  # Rate for SHA3-224
    256: 1088,  # Rate for SHA3-256
    384: 832,   # Rate for SHA3-384
    512: 576    # Rate for SHA3-512
}


def ROL64(a, n):
    return ((a >> (64 - (n % 64))) | (a << (n % 64))) & ((1 << 64) - 1) # Rotate left 64-bit integer a by n bits

def keccak_f(state):

    # Keccak round constants
    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    ]

    # Keccak round offsets
    r = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14]
    ]


    # Keccak theta function
    def theta(lanes):
        C = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4] for x in range(5)]
        D = [C[(x + 4) % 5] ^ ROL64(C[(x + 1) % 5], 1) for x in range(5)]
        return [[lanes[x][y] ^ D[x] for y in range(5)] for x in range(5)]


    # Keccak rho and pi functions
    def rho_and_pi(lanes):
        (x, y) = (1, 0)
        current = lanes[x][y]
        for t in range(24):
            (x, y) = (y, (2 * x + 3 * y) % 5)
            (current, lanes[x][y]) = (lanes[x][y], ROL64(current, (t + 1) * (t + 2) // 2))
        return lanes
    
    # Keccak chi function
    def chi(lanes):
        for y in range(5):
            T = [lanes[x][y] for x in range(5)]
            for x in range(5):
                lanes[x][y] = T[x] ^ ((~T[(x + 1) % 5]) & T[(x + 2) % 5])
        return lanes

    # Keccak iota function
    def iota(lanes, round_idx):
        lanes[0][0] ^= RC[round_idx]
        return lanes

    # Apply 24 rounds of Keccak permutation with the above functions
    for round_idx in range(24):
        state = theta(state)
        state = rho_and_pi(state)
        state = chi(state)
        state = iota(state, round_idx)

    return state


# Padding function for Keccak sponge construction
# The final message will be padded with a 10*1 pattern
def pad10star1(input_len, rate):
    pad_len = rate - (input_len % rate)
    padding = b'\x06' + b'\x00' * (pad_len - 2) + b'\x80'
    return padding



# Keccak sponge construction
def sponge(input_bytes, output_len=256):
    # Rate in bytes for SHA3-256
    rate = sha3_rates[output_len] // 8  

    # Pad the input
    padded = input_bytes + pad10star1(len(input_bytes), rate) 

    # Initialize the state to zero
    state = [[0] * 5 for _ in range(5)] 

    # Absorption phase
    for i in range(0, len(padded), rate):
        # Take a block of rate bytes
        block = padded[i:i + rate] 
        # Split the block into 8-byte chunks
        for j in range(len(block) // 8): 
            chunk = block[8 * j:8 * (j + 1)]
            # XOR the chunk into the state
            state[j % 5][j // 5] ^= int.from_bytes(chunk, 'little') 
        # Permute the state
        state = keccak_f(state) 

    # Squeezing phase
    output = b''
    while len(output) < output_len // 8:
        for y in range(5):
            for x in range(5):
                if len(output) < output_len // 8:
                    output += state[x][y].to_bytes(8, 'little')
        if len(output) < output_len // 8:
            state = keccak_f(state)  # Only permute if more output is needed

    return output[:output_len // 8]

def sha3_hash_file(file_path, output_len=256):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()
        hash_result = sponge(data, output_len) # SHA3-256 by default
        return hash_result.hex()
    except FileNotFoundError:
        return "Error: File not found."
    except Exception as e:
        return f"Error: {e}"


def main(argv):

    if len(argv) < 2 or argv[1] != "-a":
        print("Usage: python keccak.py -a RATE <FILE_PATH>")
        exit(-1)
    
    if not (argv[2] == "224" or argv[2] == "256" or argv[2] == "384" or argv[2] == "512"):
        print("Usage: python keccak.py -a RATE <FILE_PATH>")
        print("RATE must be 224, 256, 384, or 512")
        exit(-1)
    
    rate = int(argv[2])

    for file in argv[3:]:
        hash_result = sha3_hash_file(file, rate)
        print(f"SHA3-{rate} hash of the file {file}: {hash_result}")
    return

if __name__ == "__main__":
    main(sys.argv)
