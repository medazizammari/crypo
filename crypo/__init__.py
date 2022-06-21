from .encryption import sym_encryption, asym_encryption
from .encoding import encode_decode
from .hashing import hash_function, crack_hash
from .services import CLIService, StreamlitService, IOService
from .containers import Container

from dependency_injector.wiring import inject, Provide

import sys

@inject
def main(service: IOService = Provide[Container.service]):
    service.print("Welcome to crypo ! Cryptography made easy", mode='title')
    service.Menu([
        ("encoding and decoding", encode_decode),
        ("message hashing", hash_function),
        ("cracking hash", crack_hash),
        ("symmetric encryption and decryption", sym_encryption),
        ("asymmectric cryptography", asym_encryption),
    ], once=False, include_back=False, mode='sidebar').run()

container = Container()
