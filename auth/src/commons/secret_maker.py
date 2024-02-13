import secrets

from src.config import cfg

MAX_SECRET_SIZE_IN_BYTES = cfg.client_secret_size

def make_secret():
    return secrets.token_urlsafe(MAX_SECRET_SIZE_IN_BYTES)[0:MAX_SECRET_SIZE_IN_BYTES]
