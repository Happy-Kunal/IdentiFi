import os
import base64

MAX_SECRET_SIZE_IN_BYTES = 32

def make_secret():
    return base64.encodebytes(os.urandom(int(MAX_SECRET_SIZE_IN_BYTES / 8) * 6)).decode("utf-8").rstrip()

async def make_secret_async():
    return make_secret()
