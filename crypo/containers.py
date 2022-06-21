from dependency_injector import containers, providers
from .services import IOService, CLIService, StreamlitService 

class Container(containers.DeclarativeContainer):
    service = providers.Factory(
        CLIService
    )