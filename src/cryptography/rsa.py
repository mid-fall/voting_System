""" Adapted from https://stackoverflow.com/questions/30056762/rsa-encryption-and-decryption-in-python
"""
import os

import Crypto
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
import ast

class RSACipher():
    @staticmethod
    def generate_keypair(savedir='bvm_key'):
        rng = Random.new().read
        private_key = RSA.generate(1024, rng)
        public_key = private_key.publickey()
        
        head_dir, _ = os.path.split(savedir)
        if head_dir != '':
            try:
                os.mkdir(head_dir)
            except FileExistsError:
                pass
        
        with open(savedir, 'wb') as f:
            f.write(private_key.exportKey(format='PEM'))
        with open(savedir+'.pub', 'wb') as f:
            f.write(public_key.exportKey(format='PEM'))
    
    @staticmethod
    def encrypt(message, pub_key, file_msg=False, file_pub_key=True):
        if file_msg:
            with open(message, 'rb') as f:
                message = f.read()
        else:
            if hasattr(message, 'encode'):
                message = message.encode()
        if file_pub_key:
            pub_key = RSACipher.read_key(pub_key)
        cipher = PKCS1_OAEP.new(pub_key)
        return cipher.encrypt(message)

    @staticmethod
    def decrypt(ciphertext, priv_key, file_msg=False, file_priv_key=True, as_string=False):
        if file_msg:
            with open(ciphertext, 'rb') as f:
                ciphertext = f.read()
        else:
            if hasattr(ciphertext, 'encode'):
                ciphertext = ciphertext.encode()
        if file_priv_key:
            priv_key = RSACipher.read_key(priv_key)
        cipher = PKCS1_OAEP.new(priv_key)
        plaintext = cipher.decrypt(ciphertext)
        return (plaintext.decode('ASCII') if as_string else plaintext)

    @staticmethod
    def read_key(keydir):
        with open(keydir, 'r') as f:
            ext_key = f.read()
        key = RSA.importKey(ext_key)
        return key