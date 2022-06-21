import string
from itertools import product
import time
from shutil import copyfile

from crypo.utils import Menu
from hashlib import sha256, sha512, sha384, md5, sha1, sha224
from .containers import Container
from .services import IOService
from dependency_injector.wiring import inject, Provide

@inject
def hash_function(service: IOService = Provide[Container.service]):
    service.print("Hashing", mode='header')
    message = service.input("enter the message to hash")
    hashing_algorithm = service.Menu([
        ("SHA1 ", lambda: sha1_hash),
        ("SHA224", lambda: sha224_hash),
        ("SHA256", lambda: sha256_hash),
        ("SHA384", lambda: sha384_hash),
        ("SHA512", lambda: sha512_hash),
        ("MD5", lambda: md5_hash),
    ],choice_message="choose a hashing algorithm").run()
    hashed = hashing_algorithm(message)
    service.print("hashed:")
    service.print(hashed, mode='code')

def sha1_hash(message):
    return sha1(message.encode()).hexdigest()

def sha224_hash(message):
    return sha224(message.encode()).hexdigest()

def sha256_hash(message):
    return sha256(message.encode()).hexdigest()

def sha384_hash(message):
    return sha384(message.encode()).hexdigest()

def sha512_hash(message):
    return sha512(message.encode()).hexdigest()

def md5_hash(message):
    return md5(message.encode()).hexdigest()

def hash_word(word, hash_algo):
    if hash_algo.upper() == 'SHA256':
        return sha256(word.encode()).hexdigest()
    elif hash_algo.upper() == 'SHA512':
        return sha512(word.encode()).hexdigest()
    elif hash_algo.upper() == 'SHA384':
        return sha384(word.encode()).hexdigest()
    elif hash_algo.upper() == 'SHA1':
        return sha1(word.encode()).hexdigest()
    elif hash_algo.upper() == 'MD5':
        return md5(word.encode()).hexdigest()
    elif hash_algo.upper() == 'SHA224':
        return sha224(word.encode()).hexdigest()

@inject
def detect_hash(hashed, service: IOService = Provide[Container.service]):
    if len(hashed) == 128:
        return 'SHA512'
    elif len(hashed) == 96:
        return 'SHA384'
    elif len(hashed) == 64:
        return 'SHA256'
    elif len(hashed) == 40:
        return 'SHA1'
    elif len(hashed) == 32:
        return 'MD5'
    elif len(hashed) == 56:
        return 'SHA224'
    else:
        service.print('Could not auto detect hash type\n', mode='warning')
        return None


@inject
def crack_hash(service: IOService = Provide[Container.service]):
    service.print("Hash Cracking", mode='header')
    hached = service.input("enter the message to crack").strip()
    cracking_technique = service.Menu([
        ("Dictionary attack", lambda: dictionary_attack),
        ("Brute force attack", lambda: brute_force_attack),
    ],choice_message="choose the technique to use").run()
    
    message = cracking_technique(hached)
    service.print(message, mode='code')

@inject
def import_dict(service: IOService = Provide[Container.service]):
    source = service.read_file("Provide the dictionnary filepath")
    imported_filename = f'imported{time.strftime("%Y%m%d-%H%M%S")}.txt'
    destination = f"./crypo/dictionnaries/{imported_filename}"
    copyfile(source, destination)
    service.print("Imported", mode='success')
    return imported_filename

@inject
def dictionary_attack(hashed, service: IOService = Provide[Container.service]):
    algo = detect_hash(hashed)

    if not algo:
        return "Failed to crack hash"

    dictionary = service.Menu([
        ("Plaint text Dictionnary", lambda: "plaintext.txt"),
        ("French Dictionnary", lambda: "french.txt"),
        ("English Dictionnary", lambda: "english.txt"),
        ("Import and use Dictionnary", import_dict)
    ],choice_message="choose a dictionary").run()

    service.submit(message='Submit')
    with open("./crypo/dictionnaries/" + dictionary) as dictionary:
        for line in dictionary:
            words = line.split()
            for word in words:
                hashed_word = hash_word(word, algo)
                if hashed_word == hashed:
                    return word
    return "Failed to crack hash"

    
@inject
def brute_force_attack(hashed, service: IOService = Provide[Container.service]):
    algo = detect_hash(hashed)

    charset = service.Menu([
        ("Letters", lambda: string.ascii_letters),
        ("Lowercase Letters", lambda: string.ascii_lowercase),
        ("Uppercase Letters", lambda: string.ascii_uppercase),
        ("Digits", lambda: string.digits),
        ("Alphanumerical Characters", lambda: string.digits + string.ascii_letters),
    ],choice_message="choose the charset to use").run()

    service.submit(message='Submit')

    for length in range(4, 11):
        words = product(charset, repeat=length)
        for word in words:
            word = "".join(word)
            hashed_word = hash_word(word, algo)
            if hashed_word == hashed:
                return word


