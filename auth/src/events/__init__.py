from confluent_kafka import Producer
from confluent_kafka.serialization import StringSerializer
from confluent_kafka.schema_registry import SchemaRegistryClient
from confluent_kafka.schema_registry.avro import AvroSerializer
from pydantic2avro import PydanticToAvroSchemaMaker

from src.config import cfg
from src.schemas import UserInDBSchema

from .events import KafkaEvent
from .events import DraftUserKafkaEventFactory as __UserDraftKafkaEventFactory
from .producer import KafkaProducer as __KafkaProducer


__all__ = [
    "KafkaEvent",
    "KafkaProducer",
    "UserDraftKafkaEventFactory"
]

schema_registry = SchemaRegistryClient(cfg.kafka.schema_registry.config)
producer = Producer(cfg.kafka.producer.config)

KafkaProducer = __KafkaProducer(producer=producer)

UserDraftKafkaEventFactory = __UserDraftKafkaEventFactory(
    topic=cfg.kafka.topics.draft_user,

    key_serializer=StringSerializer(),

    value_serilizer=AvroSerializer(
        schema_registry,
        PydanticToAvroSchemaMaker(UserInDBSchema).get_schema_str(),
        lambda user, _ctx: user.model_dump()
    )
)
