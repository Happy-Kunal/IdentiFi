from abc import ABC, abstractmethod
from typing import override

from confluent_kafka.serialization import (MessageField, SerializationContext,
                                           Serializer)
from pydantic import BaseModel

from src.schemas.users import UserInDBSchema


class KafkaEvent(BaseModel):
    topic: str
    key: str | bytes
    value: str | bytes


class KafkaEventFactory(ABC):
    def __init__(self, topic: str, key_serializer: Serializer, value_serializer: Serializer):
        self.topic = topic
        self.key_serializer = key_serializer
        self.value_serializer = value_serializer

    @abstractmethod
    def __call__(self, pydantic_model: BaseModel) -> KafkaEvent:
        raise NotImplementedError




class DraftUserKafkaEventFactory(KafkaEventFactory):
    def __init__(self, topic: str, key_serializer: Serializer, value_serializer: Serializer):
        super().__init__(topic, key_serializer, value_serializer)
    

    @override
    def __call__(self, pydantic_model: UserInDBSchema) -> KafkaEvent:
        return KafkaEvent(
            topic=self.topic,

            key=self.key_serializer(
                pydantic_model.org_identifier,
                ctx=SerializationContext(
                    topic=self.topic,
                    field=MessageField.KEY
                )
            ),

            value=self.value_serializer(
                pydantic_model,
                ctx=SerializationContext(
                    topic=self.topic,
                    field=MessageField.VALUE
                )
            )
        )
