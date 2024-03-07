from abc import ABC, abstractmethod
from typing import override, Type

from confluent_kafka.serialization import (MessageField, SerializationContext,
                                           Deserializer)
from confluent_kafka.schema_registry import SchemaRegistryClient
from confluent_kafka.schema_registry.avro import AvroDeserializer
from confluent_kafka.serialization import StringDeserializer

from pydantic import BaseModel
from pydantic2avro import PydanticToAvroSchemaMaker

from src.schemas.users import DraftUserSchema


class KafkaEvent(BaseModel):
    topic: str
    key: str | bytes
    value: str | bytes


class KafkaEventDecoderFactory[T: Type[BaseModel]]:
    def __init__(self, value_deserilizer: Deserializer, cast_to: T):
        self.value_deserilizer = value_deserilizer
        self.cast_to = cast_to

    def __call__(self, event: KafkaEvent) -> T:
        return self.cast_to(
            self.value_deserilizer(
                value=event.value,
                ctx=SerializationContext(event.topic, MessageField.VALUE)
            )
        )


class DraftUserKafkaEventDecoder:
    def __init__(self, schema_registry_client: SchemaRegistryClient):
        schema = PydanticToAvroSchemaMaker(DraftUserSchema).get_schema_str()
        value_deserilizer = AvroDeserializer(
            schema_registry_client=schema_registry_client,
            schema_str=schema,
            from_dict=lambda obj, ctx:
                DraftUserSchema(**obj) if obj is not None else None
        )

        self.event_decoder_factory = KafkaEventDecoderFactory(value_deserilizer=value_deserilizer, cast_to=DraftUserSchema)


    def __call__(self, event: KafkaEvent) -> DraftUserSchema:
        return self.event_decoder_factory(event=event)


        
