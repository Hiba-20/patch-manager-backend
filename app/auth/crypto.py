from cryptography.fernet import Fernet
import os


def get_cipher() -> Fernet:
    key = os.getenv("ENCRYPTION_KEY")
    if not key:
        raise RuntimeError(
            "ENCRYPTION_KEY not set in .env — "
            "generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return Fernet(key.encode())


def encrypt_value(plain: str) -> str:
    if not plain:
        return plain
    return get_cipher().encrypt(plain.encode()).decode()


def decrypt_value(token: str) -> str:
    if not token:
        return token
    try:
        return get_cipher().decrypt(token.encode()).decode()
    except Exception:
        return token
