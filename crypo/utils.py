from collections.abc import Iterable
from typing import Optional
import sys
from operator import itemgetter
from abc import ABC, abstractmethod, ABCMeta
import uuid

import streamlit as st

def rerun():
    raise st.script_runner.RerunException(st.script_request_queue.RerunData(None))

class Menu(ABC):
    choices = []
    
    '''Display a menu and respond to choices when run.'''
    def __init__(self, choices: Optional[Iterable] = None, include_quit: bool = True,
                 once: bool = True, choice_message: str = "Choose an option: ",
                 quit_message: Optional[str] = "Quitting", include_back: bool = False,
                 mode: str = '', empty_message: str = "No options"
    ):
        if not choices:
            choices = []
        self.choices = list(choices)
        self.once = once
        self.choice_message = choice_message
        self.include_back = include_back
        self.include_quit = include_quit
        self.empty_message = empty_message
        
        self.quit_message = quit_message
        self.mode = mode
    
    @property
    def items(self):
        result = self.choices.copy()
        if self.include_quit:
            result.append(("Quit", self.quit))

        if self.include_back:
            result.append(("Back", lambda : "GO_BACK"))
        return result
    
    @property
    def actions(self):
        return list(map(itemgetter(1), self.items))
    
    @property
    def descriptions(self):
        return list(map(itemgetter(0), self.items))

    @abstractmethod
    def display_menu(self):
        pass

    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def quit(self):
        pass

class StreamlitMenu(Menu):
    @property
    def placeholder(self):
        if self.mode == 'sidebar':
            return st.sidebar
        else:
            return st

    def display_menu(self) -> Optional[int]:
        option = self.placeholder.selectbox(
            self.choice_message, list(enumerate(self.descriptions, start=1)),
            format_func=itemgetter(1)
        )
        if option:
            return option[0]
        return None
    
    def run(self):
        '''Display the menu and respond to choices.'''
        while True:
            choice = self.display_menu()
            if not choice:
                st.warning(self.empty_message)
                st.stop()
            action = self.actions[choice-1]
            if action:
                result = action()
                if result == "GO_BACK":
                    break
            if self.once:
                return result
        return result
    
    @property
    def items(self):
        return self.choices

    def quit(self):
        self.placeholder.write("Terminated")
        if not self.placeholder.button("Restart"):
            st.stop()

class CLIMenu(Menu):
    def display_menu(self):
        if not self.actions or (len(self.actions) == 1 and self.actions[0]==self.quit):
            print(f"{Color.WARNING}{self.empty_message}{Color.ENDC}")
            self.quit()
            return
        
        message_template = "{index}- {description}"

        print("\n".join(
            [
                message_template.format(index=index, description=description)
                for index, description in enumerate(self.descriptions, start=1)
            ]
        ), "\n")
        return True

    def run(self):
        '''Display the menu and respond to choices.'''
        while True:
            self.display_menu()
            try:
                choice = int(input(self.choice_message + "\n"))
                action = self.actions[choice-1]
            except:
                print("Invalid input, retry...")
                continue

            if action:
                result = action()
                if result == "GO_BACK":
                    break
            if self.once:
                return result
        return result

    def quit(self):
        if self.quit_message:
            print(self.quit_message)
        sys.exit(0)


class MenuProvider(ABC):
    @abstractmethod
    def provide_menu(self) -> Menu:
        pass

class Color:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


if __name__ == "__main__":
    CLIMenu([("hello", lambda: print("hello"))], once=True, include_quit=True, include_back=False).run()