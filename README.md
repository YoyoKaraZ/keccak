# Keccak/SHA3 Implementation

This project provides a Python implementation of the Keccak hashing algorithm, which forms the basis of the SHA3 family of cryptographic hash functions. The implementation includes support for SHA3-224, SHA3-256, SHA3-384, and SHA3-512 hash lengths.

## Features

- **Keccak Permutation Function**: Implements the core Keccak permutation logic.
- **Padding**: Uses the `10*1` padding rule required by the Keccak sponge construction.
- **Sponge Construction**: Absorbs input data and squeezes output to generate the final hash.
- **Customizable Hash Lengths**: Supports SHA3-224, SHA3-256, SHA3-384, and SHA3-512.

## How It Works

The program takes an input file and computes its cryptographic hash using the Keccak-based SHA3 algorithm. The user specifies the desired hash length (224, 256, 384, or 512 bits).

### Core Components

1. **Keccak Permutation Function**: The heart of the algorithm, which involves multiple rounds of transformations:
   - **Theta**: Ensures diffusion by XORing slices of the state.
   - **Rho and Pi**: Rotate and permute bits for spreading the input.
   - **Chi**: Non-linear mixing of bits.
   - **Iota**: Adds round constants for symmetry breaking.

2. **Padding**: Ensures the input message is correctly aligned to the block size using the `10*1` rule.

3. **Sponge Construction**:
   - **Absorption Phase**: XORs input blocks into the state and applies permutations.
   - **Squeezing Phase**: Extracts hash bits from the state and applies permutations as needed.

### Usage

The program is run via the command line. Users can specify the desired hash length and input files for hashing.

#### Command-Line Arguments

- `-a RATE`: Specifies the hash length. Accepted values are `224`, `256`, `384`, or `512`.
- `<FILE_PATH>`: One or more files to hash.

#### Example

```bash
python keccak.py -a 256 example.txt
```

This computes the SHA3-256 hash of `example.txt`.

## Requirements

- Python 3.x

## Implementation Details

### Functions

1. `ROL64(a, n)`: Performs a 64-bit rotate-left operation on `a` by `n` bits.
2. `keccak_f(state)`: Applies the Keccak permutation to the state matrix.
3. `pad10star1(input_len, rate)`: Generates padding based on the `10*1` rule.
4. `sponge(input_bytes, output_len)`: Implements the Keccak sponge construction.
5. `sha3_hash_file(file_path, output_len)`: Computes the hash of a file.

### File Structure

- **`keccak.py`**: Main program containing the Keccak implementation and entry point.

## Limitations

- Only processes files as input. String or stream input is not supported in the current implementation.
- No threading or parallelism for performance optimization.
