#interfacing with mysql
# hashlib for hashing password - keep all stored passwords hashed and secure when in database
import bcrypt
# regex to validate emails
import re
#
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy.sql import text
#2fa
import time, datetime
import pyotp
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=os.urandom(16),
    iterations=480000,
    # potentially dangerous?
    backend = default_backend()
)
password="abcdefg".encode()
key=base64.urlsafe_b64encode(kdf.derive(password)) # key
secret=pyotp.random_base32().encode()
encrypted = Fernet(key).encrypt(secret)
print(key)
print(secret)
print(encrypted)
key=b'GJgx4Gi5Hvh3jPMsH4QSMDcoNdRJrhG8mivoXEuUxfw='
decrypted = Fernet(b'GJgx4Gi5Hvh3jPMsH4QSMDcoNdRJrhG8mivoXEuUxfw=').decrypt(b'gAAAAABn9Nq-odMHMz7cWPrAc0dnvEsgB12eNxhrh6eJVtK9FdCHw7U7GNQiMvVSLcCCAZ5FbuESG7z2qehFbCZOn8es4l1LKyZlUrTKd_lu6reBSw6FFF5G_bYagTlQ2pPd6t6yn47C')
print(decrypted.decode())
if secret == decrypted:
    print("test succies")