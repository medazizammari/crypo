from abc import ABC, abstractmethod, ABCMeta
import streamlit as st
import getpass
import time

from .utils import CLIMenu, StreamlitMenu, Color


class IOService(ABC):
    @property
    @abstractmethod
    def Menu(self):
        pass

    @abstractmethod
    def input(self, message: str) -> str:
        pass

    @abstractmethod
    def print(self, message: str, mode: str ='info'):
        pass
    
    @abstractmethod
    def read_file(self, message: str, key: str = None) -> bytes:
        pass
    
    @abstractmethod
    def getpass(self, message: str) -> str:
        pass
    
    def submit(self, message: str = "Done", key: str = None):
        pass

class CLIService(IOService):
    @property
    def Menu(self):
        return CLIMenu
    
    def input(self, message: str) -> str:
        return input(message + "\n")
    
    def print(self, message: str, mode: str =''):
        color = Color.HEADER
        if mode=='code':
            color = Color.OKBLUE
        
        elif mode=='success':
            color = Color.OKGREEN
        
        elif mode=='title':
            color = Color.BOLD
        
        elif mode=='header':
            color = Color.HEADER
        
        elif mode=='info':
            color = Color.OKCYAN
        
        elif mode=='warning':
            color = Color.WARNING
        
        print(f"{color}{message}{Color.ENDC}")
    
    def read_file(self, message: str, key: str = None) -> bytes:
        filename = self.input(message)
        return filename
    
    def getpass(self, message: str) -> str:
        return getpass.getpass(message)

    
class StreamlitService(IOService):
    @property
    def Menu(self):
        return StreamlitMenu
    
    def input(self, message: str) -> str:
        result = st.text_input(message)
        if not result:
            st.stop()
        return result
        
    def print(self, message: str, mode: str = ''):
        if mode=='code':
            st.code(message)
        
        elif mode=='success':
            st.success(message)
        
        elif mode=='title':
            st.title(message)
        
        elif mode=='header':
            st.header(message)
        
        elif mode=='info':
            st.info(message)
        
        elif mode=='warning':
            st.warning(message)
        
        else:
            st.write(message)
        
    def read_file(self, message: str, key: str = None) -> bytes:
        file_uploader = st.file_uploader(message, key=key)
        if not file_uploader:
            st.stop()
        buffer = file_uploader.read()
        filename = f'uploaded_{str(time.time())}.bin'
        filepath = f"./crypo/uploaded/{filename}"
        f = open(filepath, 'wb')
        f.write(buffer)
        f.close()
        return filepath

    def getpass(self, message: str) -> str:
        result = st.text_input(message, type="password")
        if not result:
            st.stop()
        return result
    
    def submit(self, message: str = "Done", key: str = None):
        button = st.button(message, key=key)
        if not button:
            st.stop()
        

