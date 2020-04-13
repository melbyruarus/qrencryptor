"""A python decryption tool as a fallback if php is broken for some reason.

Requires that pycryptodome is installed. Tested on brew-installed Python3 running on 10.15.3.

Steps to setup:
- install homebrew
- brew install python
- pip3 install pycryptodome

Run:
- python3 path/to/decrypt.py
"""

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from getpass import getpass
from codecs import decode

password = getpass()
ciphertext_b64 = input("first base64_decode parameter from the QR code (ciphertext): ")
salt_b64 = input("second base64_decode parameter from the QR code (salt): ")
iv_b64 = input("third base64_decode parameter from the QR code (iv): ")

print()

salt = b64decode(salt_b64)
iv = b64decode(iv_b64)
key = PBKDF2(password, salt, 32, count=10000000, hmac_hash_module=SHA512)

cipher = AES.new(key, AES.MODE_CBC, iv=iv)
plaintext = unpad(cipher.decrypt(b64decode(ciphertext_b64)), AES.block_size)

print(decode(plaintext, 'utf-8'))
