from typing import Protocol

from .events import KafkaEvent


class ProducerInterface(Protocol):
    def produce(self, topic: str, key: str | bytes, value: str | bytes):
        ...
    def flush(self, timeout: float):
        ...
    def __len__(self) -> int:
        ...
    

class KafkaProducer:
    def __init__(
        self,
        producer: ProducerInterface
    ) -> None:
        
        self.producer = producer

    
    def publish(self, event: KafkaEvent):
        self.producer.produce(
            topic=event.topic,
            key=event.key,
            value=event.value
        )

    def flush(self, timeout: float = 10.0):
        self.producer.flush(timeout)

    def pending_mesg(self):
        return len(self.producer)
    
