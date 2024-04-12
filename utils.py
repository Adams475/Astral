from pathlib import Path
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.PublicKey import RSA
import hashlib
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes

debug = True


# Called on startup to check if a new encrypted key file was made
# If so, replace the old encrypted key files with the new ones.
def check_new_keys():
    new_fp_enc_dec = Path("server/new_encrypted_server_enc_dec_pub_prv.txt")
    new_fp_signing = Path("server/new_encrypted_server_signing_verification_pub_prv.txt")
    old_fp_enc_dec = Path("server/encrypted_server_enc_dec_pub_prv.txt")
    old_fp_signing = Path("server/encrypted_server_signing_verification_pub_prv.txt")
    if new_fp_enc_dec.exists():
        old_fp_enc_dec.unlink()
        old_fp_signing.unlink()
        new_fp_enc_dec.rename("server/encrypted_server_enc_dec_pub_prv.txt")
        new_fp_signing.rename("server/encrypted_server_signing_verification_pub_prv.txt")


def hash_message(message):
    return SHA256.new(message)


# Encrypts an RSA key that was imported into pycryptodome
def encrypt_rsa_key(decrypted_rsa_key, password):
    hashed_pw = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(hashed_pw[:16], AES.MODE_CFB, hashed_pw[16:])
    # Must convert key back from PyCryptodome object back to original byte array
    exported_key = decrypted_rsa_key.export_key()
    encrypted_data = cipher.encrypt(exported_key)
    return encrypted_data


def decrypt_rsa_private_key(encrypted_rsa_key_file, password):
    # Derive AES key and IV from the password
    hashed_pw = hashlib.sha256(password.encode()).digest()
    # Decrypt RSA keys using AES-128 in CFB mode
    with open(encrypted_rsa_key_file, 'r') as f:
        encrypted_data = f.read()  # Reads in as ASCII hexadecimal
        new_data = bytes.fromhex(encrypted_data.strip())  # Convert to bytes object from string of hex
        cipher = AES.new(hashed_pw[:16], AES.MODE_CFB, hashed_pw[16:])
        decrypted_data = cipher.decrypt(new_data)
    # Load RSA keys
    rsa_private_key = RSA.import_key(decrypted_data)
    return rsa_private_key


def load_rsa(file_path):
    with open(file_path, "r") as key_file:
        key_data = key_file.read()
        pk = RSA.import_key(key_data)
    return pk


def encrypt_message(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message)
    return encrypted_message


def decrypt_message(message, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(message)
    return decrypted_message


def sign_message(message, private_key):
    signature = pkcs1_15.new(private_key).sign(message)
    return signature


def verify_message(message, public_key, signature):
    try:
        pkcs1_15.new(public_key).verify(message, signature)
        return True
    except (ValueError, TypeError):
        return False


def generate_128_bit_random_number():
    return get_random_bytes(16)


def make_hmac(key, message):
    hmac_obj = HMAC.new(key, digestmod=SHA256)
    hmac_obj.update(message)
    return hmac_obj.digest()


def encrypt_AES(key, iv):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher


def decrypt_AES():
    return
