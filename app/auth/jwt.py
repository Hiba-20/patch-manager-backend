import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from dotenv import load_dotenv

load_dotenv()

ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "1440"))


def _load_secret() -> str:
    secret = os.getenv("JWT_SECRET")
    if secret:
        return secret
    env = os.getenv("APP_ENV", "development")
    if env == "development":
        fallback = os.urandom(32).hex()
        print(f"[warn] JWT_SECRET not set. Using ephemeral dev key: {fallback}")
        return fallback
    print("[fatal] JWT_SECRET environment variable is required in production.", file=sys.stderr)
    sys.exit(1)


SECRET_KEY = _load_secret()


def create_access_token(data: dict[str, Any]) -> str:
    to_encode = data.copy()
    to_encode.update({"exp": datetime.now(timezone.utc) + timedelta(minutes=EXPIRE_MINUTES)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any] | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None
