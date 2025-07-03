import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter

def get_mode_for_block(block_index, key_bytes):
    val = key_bytes[(block_index * 2) % len(key_bytes)] + key_bytes[(block_index * 2 + 1) % len(key_bytes)]
    return 'CBC' if val % 2 == 0 else 'CTR'

def encrypt(plaintext, key):
    key_bytes = key.encode('utf-8')
    plaintext_bytes = plaintext.encode('utf-8')
    padded = pad(plaintext_bytes, AES.block_size)
    blocks = [padded[i:i+16] for i in range(0, len(padded), 16)]
    ciphertext_blocks = []
    modes_used = []
    ivs = []
    ctrs = []
    for i, block in enumerate(blocks):
        mode = get_mode_for_block(i, key_bytes)
        modes_used.append(mode)
        if mode == 'CBC':
            iv = get_random_bytes(16)
            ivs.append(iv)
            cipher = AES.new(key_bytes[:16].ljust(16, b'\0'), AES.MODE_CBC, iv)
            ct = cipher.encrypt(block)
            ciphertext_blocks.append(ct)
            ctrs.append(None)
        else:
            ivs.append(None)
            nonce = key_bytes[:8].ljust(8, b'\0')
            ctr_val = int.from_bytes(nonce, byteorder='big') + i
            ctr = Counter.new(64, prefix=nonce, initial_value=ctr_val)
            cipher = AES.new(key_bytes[:16].ljust(16, b'\0'), AES.MODE_CTR, counter=ctr)
            ct = cipher.encrypt(block)
            ciphertext_blocks.append(ct)
            ctrs.append(ctr_val)
    return ciphertext_blocks, modes_used, ivs, ctrs

def decrypt(ciphertext_blocks, modes_used, ivs, ctrs, key):
    key_bytes = key.encode('utf-8')
    plaintext_blocks = []
    for i, ct_block in enumerate(ciphertext_blocks):
        mode = modes_used[i]
        if mode == 'CBC':
            cipher = AES.new(key_bytes[:16].ljust(16, b'\0'), AES.MODE_CBC, ivs[i])
            pt = cipher.decrypt(ct_block)
            plaintext_blocks.append(pt)
        else:
            nonce = key_bytes[:8].ljust(8, b'\0')
            ctr_val = ctrs[i]
            ctr = Counter.new(64, prefix=nonce, initial_value=ctr_val)
            cipher = AES.new(key_bytes[:16].ljust(16, b'\0'), AES.MODE_CTR, counter=ctr)
            pt = cipher.decrypt(ct_block)
            plaintext_blocks.append(pt)
    padded_plaintext = b''.join(plaintext_blocks)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext.decode('utf-8')

def serialize_all(ciphertext_blocks, modes_used, ivs, ctrs):
    data = []
    for ct, mode, iv, ctr in zip(ciphertext_blocks, modes_used, ivs, ctrs):
        entry = {
            "ct": base64.b64encode(ct).decode('utf-8'),
            "mode": mode,
            "iv": base64.b64encode(iv).decode('utf-8') if iv else None,
            "ctr": ctr
        }
        data.append(entry)
    return json.dumps(data)

def deserialize_all(json_str):
    data = json.loads(json_str)
    ciphertext_blocks = []
    modes_used = []
    ivs = []
    ctrs = []
    for entry in data:
        ciphertext_blocks.append(base64.b64decode(entry["ct"]))
        modes_used.append(entry["mode"])
        ivs.append(base64.b64decode(entry["iv"]) if entry["iv"] else None)
        ctrs.append(entry["ctr"])
    return ciphertext_blocks, modes_used, ivs, ctrs

def xor_encrypt_decrypt(data_str, key_str):
    data_bytes = data_str.encode('utf-8')
    key_bytes = key_str.encode('utf-8')
    output_bytes = bytearray()
    for i in range(len(data_bytes)):
        output_bytes.append(data_bytes[i] ^ key_bytes[i % len(key_bytes)])
    return output_bytes

def main():
    print("Choose mode:\n1) Encrypt\n2) Decrypt")
    choice = input("> ").strip()
    if choice == '1':
        plaintext = input("Enter plaintext:\n> ")
        key = input("Enter key (any length, will be truncated/padded to 16 bytes for AES):\n> ")
        ct_blocks, modes_used, ivs, ctrs = encrypt(plaintext, key)
        json_str = serialize_all(ct_blocks, modes_used, ivs, ctrs)
        # XOR encrypt JSON string with key and base64 encode
        xored = xor_encrypt_decrypt(json_str, key)
        encoded = base64.b64encode(xored).decode('utf-8')
        print("\n--- ENCRYPTED OUTPUT ---")
        print(encoded)
        print("\nSave this encrypted string to decrypt later.")
    elif choice == '2':
        print("Paste encrypted string:")
        encoded = input("> ").strip()
        key = input("Enter key:\n> ")
        try:
            xored = base64.b64decode(encoded)
            json_bytes = xor_encrypt_decrypt(xored.decode('latin1'), key)  # decode as latin1 to get back bytes
            json_str = json_bytes.decode('utf-8')
            ct_blocks, modes_used, ivs, ctrs = deserialize_all(json_str)
            decrypted = decrypt(ct_blocks, modes_used, ivs, ctrs, key)
            print("\n--- DECRYPTED MESSAGE ---")
            print(decrypted)
        except Exception as e:
            print("Decryption failed:", e)
    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()



##This is only for education purpose!##
