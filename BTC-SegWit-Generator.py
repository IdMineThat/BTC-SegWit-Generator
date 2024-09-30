from ecdsa import SigningKey, SECP256k1
import hashlib

def compress_public_key(private_key_hex):
    # Convert private key from hex to bytes
    private_key_bytes = bytes.fromhex(private_key_hex)
    
    # Generate a signing key from the private key
    signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    
    # Get the verifying key (public key)
    verifying_key = signing_key.verifying_key
    
    # Get the compressed public key
    compressed_pubkey = verifying_key.to_string("compressed").hex()
    
    return compressed_pubkey

def sha256(data):
    return hashlib.sha256(data).digest()

def ripemd160(data):
    h = hashlib.new('ripemd160')
    h.update(data)
    return h.digest()

def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def bech32_hrp_expand(s):
    return [ord(x) >> 5 for x in s] + [0] + [ord(x) & 31 for x in s]

def bech32_verify_checksum(hrp, data):
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data + [0, 0, 0, 0, 0, 0]
    polymod = bech32_polymod(values) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def convert_to_bech32(compressed_pubkey):
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    HRP = "bc"  # Human-readable part for Bitcoin mainnet

    print("Compressed Public Key:", compressed_pubkey)

    # Step 2: SHA-256 hash
    sha256_hash = sha256(bytes.fromhex(compressed_pubkey))
    print("SHA-256 Hash:", sha256_hash.hex())

    # Step 3: RIPEMD-160 hash
    ripemd160_hash = ripemd160(sha256_hash)
    print("RIPEMD-160 Hash:", ripemd160_hash.hex())

    # Step 4: Convert to binary (5 bits)
    binary_data = ''.join(format(byte, '08b') for byte in ripemd160_hash)
    print("Binary Data:", binary_data)

    # Step 5: Convert binary string to integers
    values = []
    for i in range(0, len(binary_data), 5):
        chunk = binary_data[i:i+5]
        value = int(chunk, 2)
        values.append(value)

    # Add witness version byte (0) to the beginning of the data
    witness_version = 0
    values = [witness_version] + values
    print("Values for Bech32 (with witness version):", [f"{value:02x}" for value in values])

    # Step 7: Compute checksum
    checksum = bech32_create_checksum(HRP, values)
    checksum_hex = ''.join(f"{value:02x}" for value in checksum)
    print("Checksum (Hex):", checksum_hex)

    # Step 10: Map to Bech32 characters
    bech32_address = HRP + '1' + ''.join(CHARSET[value] for value in values + checksum)
    return bech32_address

def main():
    private_key_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    compressed_pubkey = compress_public_key(private_key_hex)
    bech32_address = convert_to_bech32(compressed_pubkey)
    print("Bech32 Address:", bech32_address)

if __name__ == "__main__":
    main()
