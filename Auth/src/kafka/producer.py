from .events import EventInterface

class KafkaProducer:
    def __init__(self):
        pass
    
    @classmethod
    async def publish(cls, event: EventInterface):
        raise NotImplementedError
