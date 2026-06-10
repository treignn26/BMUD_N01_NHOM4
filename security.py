import os
import re
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KDF_ITERATIONS = 200_000


def generate_kdf_salt():
    return base64.b64encode(os.urandom(16)).decode("utf-8")


def derive_vault_key(master_password, kdf_salt):
    salt = base64.b64decode(kdf_salt)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )

    key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key).decode("utf-8")


def encrypt_password(password, vault_key):
    cipher = Fernet(vault_key)
    return cipher.encrypt(
        password.encode()
    ).decode()


def decrypt_password(token, vault_key):
    cipher = Fernet(vault_key)
    return cipher.decrypt(
        token.encode()
    ).decode()


def check_password_strength(password):

    score = 0

    if len(password) >= 8:
        score += 1

    if re.search(r"[A-Z]", password):
        score += 1

    if re.search(r"[a-z]", password):
        score += 1

    if re.search(r"\d", password):
        score += 1

    if re.search(r"[!@#$%^&*()_+=\-]", password):
        score += 1

    if score <= 2:
        return "Yếu"

    elif score <= 4:
        return "Trung bình"

    return "Mạnh"
