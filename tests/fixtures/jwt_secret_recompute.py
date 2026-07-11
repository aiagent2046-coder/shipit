"""Settings loaded at import time — mirrors a real FastAPI starter bug:
the JWT secret default is evaluated once at class-body execution, so it
silently rotates on every process restart, invalidating all previously
issued tokens.
"""
import os
import secrets


class Settings:
    SECRET_KEY: str = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
    JWT_AUDIENCE: str = os.getenv("JWT_AUDIENCE", "*")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
