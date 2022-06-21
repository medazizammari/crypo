import os
import base64
from base64 import b64encode, b64decode
import hashlib
import shelve
from struct import pack

import cryptography
from cryptography.fernet import Fernet
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto import Random
from Crypto.Cipher import DES3
from Crypto.Cipher import Blowfish
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, dh, padding
from cryptography.x509 import ObjectIdentifier
from dependency_injector.wiring import inject, Provide

from .keys import KeyPair, KEYRING
from .containers import Container
from .services import IOService

@inject
def sym_encryption(service: IOService = Provide[Container.service]):
    service.print("Symmetric Encryption", mode='header')
    service.Menu([
        ("symmetric encryption of a message", sym_encrypt),
        ("symmetric decryption of an encrypted message", sym_decrypt)
    ]).run()

@inject
def sym_encrypt(service: IOService = Provide[Container.service]):
    message = service.input("enter the message to encrypt")
    algorithm = service.Menu([
        ("Fernet Encryption", lambda: fernet_encryption),
        ("AES Encryption", lambda: aes_encryption),
        ("DES Encryption", lambda: des_encryption),
        ("blowfish Encryption", lambda: blowfish_encryption),
    ], choice_message="choose an encryption algorithm").run()
    password = service.getpass("enter the password")
    encrypted = algorithm(message, password)
    service.print("encrypted:")
    service.print(encrypted, mode='code')
    
@inject
def sym_decrypt(service: IOService = Provide[Container.service]):
    message = service.input("enter the message to decrypt")
    algorithm = service.Menu([
        ("Fernet Decryption", lambda: fernet_decryption),
        ("AES Decryption", lambda: aes_decryption),
        ("DES Decryption", lambda: des_decryption),
        ("blowfish Decryption", lambda: blowfish_decryption),
    ], choice_message="choose a decryption algorithm").run()
    password = service.getpass("enter the password")
    decrypted = algorithm(message, password)
    service.print("decrypted:")
    service.print(decrypted, mode='code')

class Salt:
    salts = shelve.open(f"./crypo/salts", writeback=True)

    @classmethod
    def set_salt(cls, key: str, salt):
        cls.salts[key] = salt
        cls.salts.sync()
    
    @classmethod
    def get_salt(cls, key: str):
        return cls.salts[key]
    
class Fernet_algorithm:
    key = None

    @classmethod
    def encrypt(cls, message, password):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(key)
        encrypted = fernet.encrypt(message.encode()).decode('ascii')
        Salt.set_salt(encrypted, salt)
        return encrypted

    @classmethod
    def decrypt(cls, message, password):
        salt = Salt.get_salt(message)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(key)
        decrypted = fernet.decrypt(message.encode()).decode('ascii')  
        return decrypted
    

def fernet_encryption(message, password):
    encrypted = Fernet_algorithm.encrypt(message,password)
    return encrypted

def fernet_decryption(message, password):
    decrypted = Fernet_algorithm.decrypt(message,password)
    return decrypted



class AES_algorithm:
    salt = None
    nonce = None
    tag = None

    @staticmethod 
    def encrypt(message, password):
        salt = get_random_bytes(AES.block_size)
        private_key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        cipher_config = AES.new(private_key, AES.MODE_GCM)
        cipher_text,tag = cipher_config.encrypt_and_digest(message.encode('utf-8'))
        encrypted = b64encode(cipher_text).decode('utf-8')
        Salt.set_salt(encrypted, (salt, cipher_config.nonce, tag))
        return encrypted
    
    @staticmethod
    def decrypt(message, password):
        salt, nonce, tag = Salt.get_salt(message)
        cipher_text = b64decode(message)
        private_key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(cipher_text, tag)
        return decrypted.decode("utf-8")

def aes_encryption(message, password):
    encrypted = AES_algorithm.encrypt(message,password)
    return encrypted

def aes_decryption(message, password):
    decrypted = AES_algorithm.decrypt(message, password)
    return decrypted

class DES_algorithm:
    block_size = 16
    key = None
    iv = None

    @staticmethod
    def encrypt(message, password):
        DES_algorithm.key = hashlib.sha256(password.encode("utf-8")).digest()[:DES_algorithm.block_size]
        DES_algorithm.iv = Random.new().read(DES3.block_size)
        cipher = DES3.new(DES_algorithm.key, DES3.MODE_OFB, DES_algorithm.iv)
        encrypted = cipher.encrypt(message.encode('utf-8'))
        return b64encode(encrypted).decode('utf-8') 

    @staticmethod
    def decrypt(message, password):
        cipher = DES3.new(DES_algorithm.key, DES3.MODE_OFB, DES_algorithm.iv)
        decrypted = cipher.decrypt(b64decode(message))
        return decrypted.decode('utf-8')

def des_encryption(message, password):
    encrypted = DES_algorithm.encrypt(message, password) 
    return encrypted 

def des_decryption(message, password):
    decrypted = DES_algorithm.decrypt(message,password)
    return decrypted



## Blowfish algorithme ## decryption Data must be padded to 8 byte boundary in CBC mode
class Blowfish_algorithm:
    @staticmethod
    def encrypt(message, password):
        bs = Blowfish.block_size
        key = password.encode("utf-8")
        cipher = Blowfish.new(key, Blowfish.MODE_CBC)
        plen = bs - len(message) % bs
        padding = [plen]*plen
        padding = pack('b'*plen, *padding)
        encrypted =cipher.iv + cipher.encrypt(message.encode('utf-8') + padding)
        return b64encode(encrypted).decode('utf-8')
    
    @staticmethod
    def decrypt(message, password):
        message = b64decode(message)
        bs = Blowfish.block_size
        iv = message[:bs]
        ciphertext = message[bs:]

        key = password.encode("utf-8")
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        decrypted =cipher.decrypt(ciphertext)
        last_byte = decrypted[-1]
        decrypted = decrypted[:- (last_byte if type(last_byte) is int else ord(last_byte))]
        return decrypted.decode('utf-8')

def blowfish_encryption(message, password):
    encrypted = Blowfish_algorithm.encrypt(message,password)
    return encrypted

def blowfish_decryption(message, password):
    decrypted = Blowfish_algorithm.decrypt(message, password)
    return decrypted


def asym_encrypt_sign():
    operations = ["encrypt", "sign"]
    key_pair = KeyPair.generate()
    key_pair.provide_menu(filter_obj=operations).run()

def asym_decrypt_verify():
    operations = ["decrypt", "verify"]
    key = KEYRING.keys_menu().run()
    key.provide_menu(filter_obj=operations).run()


def manage_keys():
    KEYRING.provide_menu().run()

@inject
def asym_encryption(service: IOService = Provide[Container.service]):
    service.print("Asymmetric Encryption", mode='header')
    service.Menu([
        ("generate key pair and encrypt/sign a message", asym_encrypt_sign),
        ("decrypt/verify a message using existing key pair", asym_decrypt_verify),
        ("key management", manage_keys)
    ]).run()
    

