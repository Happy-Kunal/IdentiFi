# Resources For Interface In Python:
# https://www.scaler.com/topics/interface-in-python/


from abc import ABC, abstractmethod
from typing import Union



class EventInterface(ABC):
    @abstractmethod
    def get_topic(self) -> str:...

    @abstractmethod
    def get_value(self) -> Union[str, bytes]:...

    @abstractmethod
    def get_key(self) -> Union[str, bytes]:...


class PrincipalUserWorkerDraftEvent(EventInterface):
    """
    Dummy Implementation as of now.
    """

    def __init__(self, *args, **kwargs):
        self.topic = "PrincipalUserWorkerDraftEvent"
    
    def get_topic(self) -> str:
        return self.topic
    
    def get_value(self) -> Union[str, bytes]:
        return "fake value"
    
    def get_key(self) -> Union[str, bytes]:
        return "fake key"
