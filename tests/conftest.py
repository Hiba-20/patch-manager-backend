"""Disable rate limiting and configure test DB."""

import os

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("JWT_SECRET", "test-secret-key")
os.environ.setdefault("ADMIN_EMAIL", "admin@test.com")
os.environ.setdefault("ADMIN_PASSWORD", "AdminPass123!")
os.environ.setdefault("CORS_ORIGINS", "*")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
