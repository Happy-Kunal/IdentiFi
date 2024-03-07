from __future__ import annotations
from typing import Tuple, Type

from enum import Enum

from pydantic import BaseModel, Field
from pydantic import HttpUrl, AnyUrl

from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource
)


class AutoOffsetResetEnum(str, Enum):
    SMALLEST = "smallest"
    EARLIEST = "earliest"
    BEGINING = "beginning"
    LARGEST = "largest"
    LATEST = "latest"
    END = "end"
    ERROR = "error"


class PartitionAssignmentStrategyEnum(str, Enum):
    RANGE = "range"
    ROUND_ROBIN = "roundrobin"
    COOPERATIVE_STICKY = "cooperative-sticky"




class Consumer(BaseModel):
    config: ConsumerConfig

class ConsumerConfig(BaseModel):
    bootstarp_servers: AnyUrl                                      = Field(alias="bootstrap.servers")
    group_id: str                                                  = Field(alias="group.id")
    auto_offset_reset: AutoOffsetResetEnum                         = Field(alias="auto.offset.reset")
    enable_auto_commit: bool                                       = Field(alias="enable.auto.commit")
    partition_assignment_strategy: PartitionAssignmentStrategyEnum = Field(alias="partition.assignment.strategy")
    client_id: str                                                 = Field(alias="client.id")


class Events(BaseModel):
    kafka: Kafka

class Kafka(BaseModel):
    consumer: Consumer
    schema_registry: SchemaRegistry

class SchemaRegistry(BaseModel):
    config: SchemaRegistryConfig

class SchemaRegistryConfig(BaseModel):
    url: HttpUrl
    basic_auth_user_info: str = Field(alias="basic.auth.user.info")




class Config(BaseSettings):
    model_config = SettingsConfigDict(yaml_file='config.yaml', env_nested_delimiter="__")
    
    events: Events

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        return (
            YamlConfigSettingsSource(settings_cls),
            *super().settings_customise_sources(
                settings_cls=settings_cls,
                init_settings=init_settings,
                env_settings=env_settings,
                dotenv_settings=dotenv_settings,
                file_secret_settings=file_secret_settings
            )
        )
