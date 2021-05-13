# import pastebin #not working in python3
import hashlib
from hashlib import sha256
import zlib

import Crypto
from Crypto.Hash import SHA256

from AESCipher import aes_encrypt, aes_decrypt

charset_homograph = ['Ѕ', 'І', 'Е', 'Ј', 'А', 'В', 'М', 'К', 'Н', 'О', 'Р', 'С', 'Т', 'Х', 'а', 'е', 'о', 'р', 'с',
                     'у', 'ѕ', 'і',
                     'ј', '‚']  # Russian Cyrillic Alphabet. Seems equal to the below
charset_occidental = ['S', 'I', 'E', 'J', 'A', 'B', 'M', 'K', 'H', 'O', 'P', 'C', 'T', 'X', 'a', 'e', 'o', 'p',
                      'c', 'y', 's',
                      'i', 'j', ',']  # Occidental Alphabet
END_CHARACTER = "​"


# TODO Cambiar logica
def hide(message, secret, key):
    """
    Hide the secret (encrypted) with the key into the message.

    :param message: Message where we are hiding the information
    :param secret: Secret we are hiding in the message
    :param key: Key used to encrypt the secret after compressing the bits
    :return: The message with the secret.
    """
    # Get the bytes of the secret
    secret_bytes = secret.encode('utf-8')
    # Compress the secret
    compressed_bytes = zlib.compress(secret_bytes, 9)
    # Encrypt the bytes
    encrypted_bytes = aes_encrypt(compressed_bytes, password_hasher(key))
    # Transform the encrypted secret into bits
    encrypted_bits = bytes_to_bitstring(encrypted_bytes)
    # For checking the max length
    len_encrypted_bits = len(encrypted_bits)


    max_length = check_max_secret_length(message)
    if max_length < len_encrypted_bits:
        print(f'The program can only hide {str(max_length)} bits.')
        exit(-1)

    binary_string_counter = 0
    finished = False

    result = []

    for c in message:
        if binary_string_counter < len_encrypted_bits:
            # We should encode the message
            if c in charset_occidental:
                if encrypted_bits[binary_string_counter] == "0":  # Use Occidental
                    result.append(c)
                else:  # Use cyrillic
                    result.append(charset_homograph[charset_occidental.index(c)])
                binary_string_counter += 1
            elif c in charset_homograph:
                if encrypted_bits[binary_string_counter] == "1":
                    result.append(c)
                else:
                    result.append(charset_occidental[charset_homograph.index(c)])
                binary_string_counter += 1
            else:
                result.append(c)
        else:
            if not finished:
                result.append(END_CHARACTER)
                finished = True
            result.append(c)
    final_result = "".join(result)
    return final_result


# TODO cambiar logica
def extract(message, key):
    """
    Extract the secret of the message

    :param message: Message with the hidden secret
    :param key: Key used to encrypt the message
    :return:
    """
    binary_secret = []
    for c in message:
        if c in charset_occidental:
            binary_secret.append("0")
        elif c in charset_homograph:
            binary_secret.append("1")
        elif c == END_CHARACTER:
            break

    # Bits to bytes
    bit_string = "".join(binary_secret)
    # Transform the bit sequence to bytes
    bytes_secret = bitstring_to_bytes(bit_string)
    # Decrypt the binary
    decrypted = aes_decrypt(bytes_secret, password_hasher(key))
    # Uncompress
    uncompress = zlib.decompress(decrypted)
    final_result = uncompress.decode('utf-8')
    return final_result


def bitstring_to_bytes(s):
    """
    Function that converts a string composed by '1's and '0' to bytes

    :param s:
    :return:
    """
    return bytearray([int(s[i:i + 8], 2) for i in range(0, len(s), 8)])


def bytes_to_bitstring(bytes):
    """
    Functions that converts a bytearray to an string composed of '1's and '0's.

    :param bytes:
    :return:
    """
    return ''.join('{:08b}'.format(x) for x in bytearray(bytes))


def check_max_secret_length(message):
    """
    It calculates the number of bits that we can hide

    :param message:
    :return:
    """
    max_len = 0
    for i in message:
        if i in charset_occidental or i in charset_homograph:
            max_len += 1
    return max_len

def check_secret_length(secret):
    # Get the bytes of the secret
    secret_bytes = secret.encode('utf-8')
    # Compress the secret
    compressed_bytes = zlib.compress(secret_bytes, 9)
    return len(bytes_to_bitstring(compressed_bytes))

def password_hasher(password):
    """
    Just hashes the password

    :param password:
    :return: 32 byte hash
    :rtype: bytes
    """
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), b'salt', 100000)
