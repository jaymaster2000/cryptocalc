#!/usr/bin/python3

"""A python program to encrypt and decrypt data to bytes
   for recording onto cold mediums."""

import sys
import hashlib
#import os
from binascii import hexlify, unhexlify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BYTE_DISPLAY_SIZE = 8

def derive_key(passphrase: str, salt: bytes = None) -> [str, bytes]:
    """converts a passphrase into a key by using or generating a salt."""
    if salt is None:
        rand_source = open("/dev/random", 'rb')
        #salt = os.urandom(8)
        salt = rand_source.read(8)
        rand_source.close()
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf8"), salt, 1000), salt


def encrypt(passphrase: str, plaintext: str) -> str:
    """encrypts plaintext data using the user supplied passphrase."""
    key, salt = derive_key(passphrase)
    aes = AESGCM(key)
    rand_source = open("/dev/random", 'rb')
    #initialization_vector = os.urandom(12)
    initialization_vector = rand_source.read(12)
    rand_source.close()
    iv_hexstring = hexlify(initialization_vector).decode("utf8")
    iv_chunks = [iv_hexstring[a: a + BYTE_DISPLAY_SIZE * 2] for a in range(0, len(iv_hexstring), \
            BYTE_DISPLAY_SIZE * 2)]
    plaintext = plaintext.encode("utf8")
    ciphertext = aes.encrypt(initialization_vector, plaintext, None)
    ciphertext_hexstring = hexlify(ciphertext).decode("utf8")
    ciphertext_chunks = [ciphertext_hexstring[i: i + BYTE_DISPLAY_SIZE * 2] for i in \
            range(0, len(ciphertext_hexstring), BYTE_DISPLAY_SIZE * 2)]
    print('=================================================================================')
    print('Encrypted:')
    print('Salt: ' + '\t\t' + hexlify(salt).decode("utf8"))
    print('IV: ' + '\t\t' + iv_chunks.pop(0))
    if iv_chunks:
        for chunks in iv_chunks:
            print('\t' + '\t' + chunks)
    print('Ciphertext: ' + '\t' + ciphertext_chunks.pop(0))
    if ciphertext_chunks:
        for chunks in ciphertext_chunks:
            print('\t' + '\t' + chunks)
    print('=================================================================================')


def decrypt(passphrase: str, ciphertext: str) -> str:
    """decrypts ciphertext data using the user supplied passphrase and the salt and iv."""
    try:
        salt, initialization_vector, ciphertext = map(unhexlify, ciphertext.split("-"))
        key, _ = derive_key(passphrase, salt)
        aes = AESGCM(key)
        plaintext = aes.decrypt(initialization_vector, ciphertext, None)
        print('=================================================================================')
        print('Decrypted:')
        print(plaintext.decode("utf8"))
        print('=================================================================================')
    except:
        print(sys.exc_info())
        print('Decryption failed, wrong key or wrong bytes?')

def usage():
    """prints usage information."""
    print('usage: aes.py [-e] [-d]')
    print('')
    print(' -e encrypt data')
    print(' -d decrypt data')
    print('')



if __name__ == "__main__":
    if len(sys.argv) == 2:
        if sys.argv[1] == '-e':
            USER_PLAINTEXT = input("Enter plaintext: ")
            USER_PASSPHRASE = input("Enter passphrase: ")
            encrypt(USER_PASSPHRASE, USER_PLAINTEXT)
        elif sys.argv[1] == '-d':
            USER_SALT = input("Enter salt: ")
            USER_IV = input("Enter iv: ")
            USER_CIPHERTEXT = input("Enter ciphertext: ")
            USER_PASSPHRASE = input("Enter passphrase: ")
            CONCAT_CIPHERTEXT = USER_SALT + '-' + USER_IV + '-' + USER_CIPHERTEXT
            decrypt(USER_PASSPHRASE, CONCAT_CIPHERTEXT)
        else:
            usage()
    else:
        usage()
