import os
import sys
from Crypto.Cipher import AES


def aes_encrypt(data, key):
    block_size = AES.block_size
    missing_padding = len(data) % block_size
    padding_bytes = block_size - missing_padding
    data += (padding_bytes * chr(padding_bytes)).encode()
    iv = os.urandom(block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(data)
    return iv + encrypted


def aes_decrypt(data, key):
    data = bytes(data)
    iv = data[:AES.block_size]
    data = data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data)
    pad = decrypted[-1]
    if not sys.version_info > (3, 0):
        pad = ord(pad)
    return decrypted[:-pad]
