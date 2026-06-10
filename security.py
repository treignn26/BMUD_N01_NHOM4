from cryptography.fernet import Fernet

KEY = b'W4uI5F1Q5gJvWmL3J4JY8mH0nL4lWw7M9mL0m2oK3xQ='

cipher = Fernet(KEY)


def encrypt_password(password):
    return cipher.encrypt(
        password.encode()
    ).decode()


def decrypt_password(password):
    return cipher.decrypt(
        password.encode()
    ).decode()

import re
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