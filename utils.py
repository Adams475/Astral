from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

debug = True


def load_rsa(file_path):
    with open(file_path, "r") as key_file:
        key_data = key_file.read()
        pk = RSA.import_key(key_data)
    return pk


def encrypt_message(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message)
    return encrypted_message
