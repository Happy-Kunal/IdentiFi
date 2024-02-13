from .events import EventInterface

class KafkaProducer:
    def __init__(self):
        pass
    
    @classmethod
    async def publish(cls, event: EventInterface):
        print("fake produced to kafka topic")
        #raise NotImplementedError
