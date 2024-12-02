import os
from cryptography.hazmat.primitives.asymmetric import padding as padding_rsa, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import padding as padding_aes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from secrets import token_bytes


# usado só para gerar o par de chaves para deixar hardcoded no esp
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with open("private_key.pem", "xb") as private_file:
        private_file.write(private_bytes)

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open("public_key.pem", "xb") as public_file:
        public_file.write(public_bytes)

    with open("public_key.pem", "r") as arquivo:
        conteudo = arquivo.read()
        print(conteudo)

    with open("private_key.pem", "r") as arquivo:
        conteudo = arquivo.read()
        print(conteudo)


def store_client_public_key(public_key: str):
    path = "public_key.pem"
    if os.path.exists(path):
        return
    with open(path, "w") as f:
        f.write(public_key)


def load_public_key():
    path = "public_key.pem"
    with open(path, "r") as f:
        loaded_public_key = serialization.load_pem_public_key(
            f.read().encode("utf-8"), backend=default_backend()
        )
    return loaded_public_key


def encrypt_rsa_public_key(message: bytes):
    loaded_public_key = load_public_key()
    padding_config = padding_rsa.PKCS1v15()
    cipher = loaded_public_key.encrypt(
        plaintext=message,
        padding=padding_config,
    )
    return cipher


def generate_aes_iv():
    return token_bytes(16)


def generate_aes_key():
    return token_bytes(16)


def store_shared_aes_key(aes_key):
    path = "shared_aes_key.key"
    with open(path, "w") as file:
        file.write(aes_key)


def load_shaerd_aes_key():
    path = "shared_aes_key.key"
    with open(path, "r") as file:
        hex_key = file.read().strip()
    aes_key = bytes.fromhex(hex_key)
    return aes_key


def encrypt_aes(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding_aes.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext


def decrypt_aes(iv: bytes, ciphertext: bytes) -> bytes:
    key = load_shaerd_aes_key()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding_aes.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext
