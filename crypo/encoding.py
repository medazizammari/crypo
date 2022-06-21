import base64
from dependency_injector.wiring import inject, Provide

from .containers import Container
from .services import IOService

@inject
def encode_decode(service: IOService = Provide[Container.service]):
    service.print("Encoding", mode='header')
    service.Menu([
        ("encoding a message", encode),
        ("decoding a code", decode),
    ]).run()

@inject
def encode(service: IOService = Provide[Container.service]):
    message = service.input("enter the message to encode")
    code = base64.b64encode(message.encode('ascii'))
    service.print(code.decode('ascii'), mode='code')

@inject
def decode(service: IOService = Provide[Container.service]):
    code = service.input("enter the code to decode")
    message = base64.b64decode(code.encode('ascii'))
    service.print(message.decode('ascii'), mode='code')