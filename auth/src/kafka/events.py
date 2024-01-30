# Resources For Interface In Python:
# https://www.scaler.com/topics/interface-in-python/


from abc import ABC, abstractmethod



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


class PrincipalUserWorkerDraftEvent(EventInterface):
    """
    Dummy Implementation as of now.
    """

    def __init__(self, *args, **kwargs):
        self.topic = "PrincipalUserWorkerDraftEvent"
    
    def get_topic(self) -> str:
        return self.topic
    
    def get_value(self) -> str | bytes:
        return "fake value"
    
    def get_key(self) -> str | bytes:
        return "fake key"
