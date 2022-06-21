from __future__ import annotations
import abc 
from abc import ABC, abstractmethod, ABCMeta
from base64 import b64encode, b64decode
from typing import Union, Optional , List, Tuple
from collections.abc import Callable
import inspect
import sys
import shelve
from functools import wraps

from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import ObjectIdentifier
import getpass

from .utils import Menu, MenuProvider
from .containers import Container
from .services import IOService
from dependency_injector.wiring import inject, Provide


class OperationsProvider(MenuProvider):
    AVAILABLE_OPERATIONS = []
    
    def get_available_operations(self) -> List[str]:
        return self.AVAILABLE_OPERATIONS
    
    @staticmethod
    def key_operation_decorator(inp: Optional[List[Tuple[str, Optional[Callable]]]] = None,
                                out: Tuple[str, Optional[Callable]] = ('', None)):
        
        if not inp:
            inp = []
        identity = lambda x: x
        def _key_operation_decorator(operation):
            @wraps(operation)
            @inject
            def inner(self, service: IOService = Provide[Container.service]):
                assert operation.__code__.co_argcount == len(inp) + 1, \
                    "decorator inp length is not equal to the operation args number"
                args = [(func or identity)(service.input(msg)) for msg, func in inp]
                result = operation(self, *args)
                msg, func = out
                func = func or identity
                result = func(result)
                if result:
                    service.print(msg)
                    service.print(result, mode='code')
            return inner
        return _key_operation_decorator
    
    @inject
    def provide_menu(self, filter_obj: Union[Callable, List[str]] = None,
                    service: IOService = Provide[Container.service]):
        if filter_obj is None:
            filter_func = (lambda x: True)
        elif isinstance(filter_obj, list):
            filter_func = lambda x: x in filter_obj
        else:
            filter_func = filter_obj
        
        return service.Menu([
            (
                operation.replace('_', ' ').title(),
                getattr(self, operation)
            ) 
            for operation in self.get_available_operations()
            if filter_func(operation)
        ], choice_message="Select operation")

class Key(OperationsProvider):
    AVAILABLE_OPERATIONS = []

    @abstractmethod
    def write(self, filename: str):
        pass

    @staticmethod
    @abstractmethod
    def read(filename: str):
        pass
    
    @classmethod
    def KEYS(cls):
        return [
            obj for _, obj in inspect.getmembers(sys.modules[__name__])
            if inspect.isclass(obj) and issubclass(obj, cls) and obj != cls
        ]
    
    @classmethod
    def from_file(cls, filename: str) -> Optional[Key]:
        key = cls.read(filename)
        key_class = next(filter(lambda _class: isinstance(key, _class.KEY_CLASS), cls.KEYS()))
        if key_class:
            return key_class(key=key)
        else:
            return None

ENCRYPT_DECORATOR = OperationsProvider.key_operation_decorator(
    inp=[("Give a message to encrypt", lambda msg: msg.encode("utf-8"))],
    out=("Encrypted message:", lambda msg: b64encode(msg).decode('utf-8'))
)
VERIFY_DECORATOR = OperationsProvider.key_operation_decorator(
    inp=[
        ("Give a signature", lambda sig: b64decode(sig)),
        ("Give a message", lambda msg: msg.encode("utf-8"))
    ],
    out=("", lambda res: "Verified" if res else "Not Verified")
)
DECRYPT_DECORATOR = OperationsProvider.key_operation_decorator(
    inp=[("Give a message to decrypt", lambda msg: b64decode(msg))],
    out=("Decrypted message:", lambda msg: msg.decode("utf-8"))
)
SIGN_DECORATOR = OperationsProvider.key_operation_decorator(
    inp=[("Give a message to sign", lambda msg: msg.encode("utf-8"))],
    out=("Signed message:", lambda msg: b64encode(msg).decode('utf-8'))
)
    

class DecryptKey(ABC):
    @abstractmethod
    def decrypt(self, encrypted_message: bytes) -> bytes:
        pass

class EncryptKey(ABC):
    @abstractmethod
    def encrypt(self, message: bytes) -> bytes:
        pass

class SignKey(ABC):
    @abstractmethod
    def sign(self, message: bytes) -> bytes:
        pass
    
class VerifyKey(ABC):
    @abstractmethod
    def verify(self, signature: bytes, message: bytes) -> bool:
        pass

class PublicKey(Key):
    KEY_CLASS = object
    AVAILABLE_OPERATIONS = ["encrypt", "verify"]

    @inject
    def __init__(self,
            key: Union[rsa.RSAPublicKey, dsa.DSAPublicKey, ec.EllipticCurvePublicKey, None] = None,
            filename: Optional[str] = None,
            service: IOService = Provide[Container.service]):
        if key:
            self.public_key = key
        elif filename:
            self.public_key = self.read(filename)
        else:
            ValueError("public_key or filename must be provided")
        
        assert isinstance(self.public_key, self.KEY_CLASS)
    
    def write(self, filename: str):
        serial_pub = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(filename, 'wb') as f: f.write(serial_pub)

    @staticmethod
    def read(filename: str) -> Union[rsa.RSAPublicKey, dsa.DSAPublicKey, ec.EllipticCurvePublicKey, None]:
        with open(filename, "rb") as key_file:
            return serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
    
    @classmethod
    def PRIVATE_KEY_CLASS(cls):
        return next(filter(
            lambda _class: _class.PUBLIC_KEY_CLASS == cls,
            PrivateKey.KEYS()
        ))
    
    @classmethod
    def ALGORITHM(cls):
        private_key_class = cls.PRIVATE_KEY_CLASS()
        if private_key_class:
            return private_key_class.ALGORITHM
        return None


class RSAPublicKey(PublicKey, EncryptKey, VerifyKey):
    KEY_CLASS = rsa.RSAPublicKey
    AVAILABLE_OPERATIONS = ["encrypt", "verify"]

    @ENCRYPT_DECORATOR
    def encrypt(self, message: bytes) -> bytes:
        return self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    @VERIFY_DECORATOR
    def verify(self, signature: bytes, message: bytes) -> bool:
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            return False
        
        return True
    


class DSAPublicKey(PublicKey, VerifyKey):
    KEY_CLASS = dsa.DSAPublicKey
    AVAILABLE_OPERATIONS = ["verify"]

    @VERIFY_DECORATOR
    def verify(self, signature: bytes, message: bytes) -> bool:
        try:
            self.public_key.verify(
                signature,
                message,
                hashes.SHA256()
            )
        except InvalidSignature:
            return False
        
        return True


class EllipticCurvePublicKey(PublicKey, VerifyKey):
    KEY_CLASS = ec.EllipticCurvePublicKey
    AVAILABLE_OPERATIONS = ["verify"]

    @VERIFY_DECORATOR
    def verify(self, signature: bytes, message: bytes) -> bool:
        try:
            self.public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature:
            return False
        
        return True

class PrivateKey(Key):
    KEY_CLASS = object
    PUBLIC_KEY_CLASS = object
    AVAILABLE_OPERATIONS = ["decrypt", "sign"]
    ALGORITHM = None

    def __init__(self,
            key: Union[rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey, None] = None,
            filename: Optional[str] = None):
        if key:
            self.private_key = key
        elif filename:
            self.private_key  = self.read(filename)
        else:
            self.private_key = self.generate()
        
        assert isinstance(self.private_key, self.KEY_CLASS)
    
    @classmethod
    @abstractmethod
    def generate(cls) -> Union[rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey]:
        pass

    @inject
    def write(self, filename: str, service: IOService = Provide[Container.service]):
        pwd = service.getpass("enter a passphrase:")
        serial_private = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(pwd.encode('utf-8'))
        )
        with open(filename, 'wb') as f: f.write(serial_private)

    @staticmethod
    @inject
    def read(filename: str, service: IOService = Provide[Container.service]) -> Union[rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey, None]:
        pwd = service.getpass("enter the passphrase")
        with open(filename, "rb") as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=pwd.encode('utf-8'),
                backend=default_backend()
            )

    def public_key(self) -> PublicKey:
        return self.PUBLIC_KEY_CLASS(key=self.private_key.public_key())


class RSAPrivateKey(PrivateKey, DecryptKey, SignKey):
    KEY_CLASS = rsa.RSAPrivateKey
    PUBLIC_KEY_CLASS = RSAPublicKey
    AVAILABLE_OPERATIONS = ["decrypt", "sign"]
    ALGORITHM = "RSA"

    @classmethod
    def generate(cls) -> Union[rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey]:
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
    
    @DECRYPT_DECORATOR
    def decrypt(self, encrypted_message: bytes) -> bytes:
        return self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    @SIGN_DECORATOR
    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )


class DSAPrivateKey(PrivateKey, SignKey):
    KEY_CLASS = dsa.DSAPrivateKey
    PUBLIC_KEY_CLASS = DSAPublicKey
    AVAILABLE_OPERATIONS = ["sign"]
    ALGORITHM = "DSA"

    @classmethod
    def generate(cls) -> Union[rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey]:
        return dsa.generate_private_key(
            key_size=2048
        )
    
    @SIGN_DECORATOR
    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(
            message,
            hashes.SHA256()
        )

class EllipticCurvePrivateKey(PrivateKey, SignKey):
    KEY_CLASS = ec.EllipticCurvePrivateKey
    PUBLIC_KEY_CLASS = EllipticCurvePublicKey
    AVAILABLE_OPERATIONS = ["sign"]
    ALGORITHM = "Elliptic Curve"
    
    @SIGN_DECORATOR
    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
    
    @classmethod
    @inject
    def generate(cls, service: IOService = Provide[Container.service]) -> Union[rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey]:
        elliptic_curve = service.Menu([
            ("SECT571R1", lambda: ec.SECT571R1),
            ("SECP192R1", lambda: ec.SECP192R1),
            ("SECP256R1", lambda: ec.SECP256R1),
            ("SECP521R1", lambda: ec.SECP521R1),
            ("SECT163R2", lambda: ec.SECT163R2),
            ("SECT163R2", lambda: ec.SECT163R2),
            ("SECT163R2", lambda: ec.SECT163R2),
            ("Lookup by Object Identifier", cls.lookup_ec_by_oid)
        ], choice_message="choose a decryption algorithm").run()

        return ec.generate_private_key(
            elliptic_curve
        )
    
    @staticmethod
    @inject
    def lookup_ec_by_oid(service: IOService = Provide[Container.service]):
        dotted_string = service.input("Give the Elliptic Curve's dotted string")
        return ec.get_curve_for_oid(ObjectIdentifier(dotted_string))


class KeyRing(OperationsProvider):
    AVAILABLE_OPERATIONS = ["import_key_pair", "import_public_key", "select_key", "new_key_pair"]
    KEYRING_DIR = "crypo/keyring"
    KEYRING_FILENAME = "keyring"
    KEYRING = shelve.open(f"{KEYRING_DIR}/{KEYRING_FILENAME}", writeback=True)

    def __init__(self, keyring_dir="crypo/keyring", keyring_filename="keyring"):
        self.KEYRING_DIR = keyring_dir
        self.KEYRING_FILENAME = keyring_filename
        if not "keys" in self.KEYRING:
            self.KEYRING["keys"] = {}
    
    def add_key_pair(self, key_pair: KeyPair):
        self.KEYRING["keys"][key_pair.key_pair_name] = {
            "type": "key_pair",
            "algorithm": key_pair.ALGORITHM
        }
    
    def add_public_key(self, key: PublicKey, key_name: str):
        self.KEYRING["keys"][key_name] = {
            "type": "public_key",
            "algorithm": key.ALGORITHM()
        }
    
    def get_key_pair(self, key_pair_name: str) -> Optional[KeyPair]:
        if key_pair_name in self.KEYRING["keys"] and \
                self.KEYRING["keys"][key_pair_name]["type"] == "key_pair":
            return KeyPair.from_files(
                f"{self.KEYRING_DIR}/private_{key_pair_name}.pem",
                f"{self.KEYRING_DIR}/public_{key_pair_name}.pem"
            )
        else:
            return None
    
    def get_public_key(self, key_name: str) -> Optional[PublicKey]:
        if key_name in self.KEYRING["keys"] and \
                self.KEYRING["keys"][key_name]["type"] == "public_key":
            return PublicKey.from_file(
                f"{self.KEYRING_DIR}/public_{key_name}.pem"
            )
        else:
            return None
    
    def keys_menu(self, service: IOService = Provide[Container.service]) -> service.Menu:
        return service.Menu(map(
            lambda key: (
                f"{key[0]}, algorithm: {key[1]['algorithm']}, type: {key[1]['type']}", 
                lambda: self.get_public_key(key[0]) if key[1]["type"]=="public_key" \
                    else self.get_key_pair(key[0])
            ),
            self.keys.items()
        ), choice_message="Select a key from the keyring")
    
    @property
    def keys(self):
        return self.KEYRING.get("keys", {})
    
    @inject
    def import_key_pair(self,
                        service: IOService = Provide[Container.service]):
        key_pair_name = service.input("Give a key pair name")
        public_key_filename = service.read_file("Give the public key's file path", key='1')
        private_key_filename = service.read_file("Give the private key's file path", key='2')
        key_pair = KeyPair.from_files(private_key_filename, public_key_filename)
        key_pair.key_pair_name = key_pair_name
        key_pair.write()
        self.add_key_pair(key_pair)
        service.print("Imported", mode='success')
    

    @inject
    def import_public_key(self, service: IOService = Provide[Container.service]):
        key_name = service.input("Give a key name")
        public_key_filename = service.read_file("Give the public key's file path")
        public_key = PublicKey.from_file(public_key_filename)
        if not public_key:
            raise ValueError("Invalid or unsupported public key file")
        
        public_key.write(f"{self.KEYRING_DIR}/public_{key_name}.pem")
        self.add_public_key(public_key, key_name)
        service.print("Imported", mode='success')
    
    def select_key(self):
        key = self.keys_menu().run()
        key.provide_menu().run()
    
    @inject
    def new_key_pair(self, service: IOService = Provide[Container.service])-> KeyPair:
        key_pair = KeyPair.generate()
        service.print("Key pair created", mode='success')
        return key_pair


KEYRING = KeyRing()


class KeyPairMeta(ABCMeta):
    def __init__(cls, *args):
        cls.ALGORITHM = cls.PRIVATE_KEY_CLASS.ALGORITHM
    

class KeyPair(OperationsProvider, metaclass=KeyPairMeta):
    
    PRIVATE_KEY_CLASS = PrivateKey
    KEYRING = KEYRING
    
    def __init__(self,
            key_pair_name: str = None,
            private_key: Optional[PrivateKey] = None,
            private_key_filename: Optional[str] = None,
            public_key: Optional[PublicKey] = None,
            public_key_filename: Optional[str] = None):
        self.key_pair_name = key_pair_name
        if private_key:
            self.private_key = private_key
        elif private_key_filename:
            self.private_key = PrivateKey.from_file(private_key_filename)
        else:
            self.private_key = self.PRIVATE_KEY_CLASS()
            self.public_key = self.private_key.public_key()
        
        assert isinstance(self.private_key, self.PRIVATE_KEY_CLASS), \
            f"private key ({self.private_key.__class__.__name__}) does not match class {self.PRIVATE_KEY_CLASS.__name__}"
        
        if public_key and (private_key or private_key_filename):
            self.public_key = public_key
        elif public_key_filename and (private_key or private_key_filename):
            self.public_key = PublicKey.from_file(public_key_filename)
        else:
            self.public_key = self.private_key.public_key()
        
        assert self.public_key.__class__ == self.private_key.PUBLIC_KEY_CLASS, \
            f"Public key and private key don't have matching classes: " \
            f"private: {self.private_key.__class__.__name__}, " \
            f"public: {self.public_key.__class__.__name__}, "
    
    def write(self):
        self.public_key.write(f"{self.KEYRING.KEYRING_DIR}/public_{self.key_pair_name}.pem")
        self.private_key.write(f"{self.KEYRING.KEYRING_DIR}/private_{self.key_pair_name}.pem")

    @classmethod
    @inject
    def generate(cls, service: IOService = Provide[Container.service]) -> KeyPair:
        if cls in KeyPair.KEY_PAIRS():
            key_pair_name = service.input("Give a key pair name")
            key_pair = cls(key_pair_name=key_pair_name)
            key_pair.write()
            cls.KEYRING.add_key_pair(key_pair)
            return key_pair
        else:
            key_pair_class = service.Menu(map(
                lambda _class: (_class.ALGORITHM, lambda: _class),
                cls.KEY_PAIRS()
            ), choice_message="Choose an algorithm").run()
            return key_pair_class.generate()
    
    @classmethod
    def from_files(cls, private_key_filename: str, public_key_filename: str) -> Optional[KeyPair]:
        private_key = PrivateKey.from_file(private_key_filename)
        key_pair_class = next(filter(lambda _class: _class.PRIVATE_KEY_CLASS == private_key.__class__, cls.KEY_PAIRS()))
        if key_pair_class:
            return key_pair_class(private_key=private_key, public_key_filename=public_key_filename)
        else:
            return None
    
    def get_available_operations(self) -> List[str]:
        return self.private_key.get_available_operations() \
            + self.public_key.get_available_operations()
    
    @classmethod
    def KEY_PAIRS(cls):
        return [
            obj for _, obj in inspect.getmembers(sys.modules[__name__])
            if inspect.isclass(obj) and issubclass(obj, cls) and obj != cls
        ]


class EncryptionKeyPair(EncryptKey, DecryptKey):
    def __init__(self, private_key: PrivateKey, public_key: PublicKey):
        self.private_key = private_key
        self.public_key = public_key
    
    def decrypt(self):
        return self.private_key.decrypt()
    
    def encrypt(self):
        return self.public_key.encrypt()

class SigningKeyPair(SignKey, VerifyKey):
    def __init__(self, private_key: PrivateKey, public_key: PublicKey):
        self.private_key = private_key
        self.public_key = public_key
    
    def sign(self):
        return self.private_key.sign()
    
    def verify(self):
        return self.public_key.verify()

class RSAKeyPair(KeyPair, EncryptionKeyPair, SigningKeyPair):
    PRIVATE_KEY_CLASS = RSAPrivateKey

class DSAKeyPair(KeyPair, SigningKeyPair):
    PRIVATE_KEY_CLASS = DSAPrivateKey

class EllipticCurveKeyPair(KeyPair, SigningKeyPair):
    PRIVATE_KEY_CLASS = EllipticCurvePrivateKey

if __name__=="__main__":
    KeyPair.generate()