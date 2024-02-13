# Resources For Interface In Python:
# https://www.scaler.com/topics/interface-in-python/


from abc import ABC, abstractmethod
from typing import override



class EventInterface(ABC):
    @abstractmethod
    def get_topic(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def get_value(self) -> str | bytes:
        raise NotImplementedError

    @abstractmethod
    def get_key(self) -> str | bytes:
        raise NotImplementedError


class PrincipalUserDraftEvent(EventInterface):
    """
    Dummy Implementation as of now.
    """

    def __init__(self, *args, **kwargs):
        self.topic = "PrincipalUserDraftEvent"
    
    @override
    def get_topic(self) -> str:
        return self.topic
    
    @override
    def get_value(self) -> str | bytes:
        return "fake value"
    
    @override
    def get_key(self) -> str | bytes:
        return "fake key"
