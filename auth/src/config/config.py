# https://docs.pydantic.dev/latest/concepts/pydantic_settings/

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, Type

from pydantic import AnyUrl, BaseModel, Field, FilePath, HttpUrl, PositiveInt
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource
)


class AstraCassandra(BaseModel):
    keyspace: str
    client_id: str
    client_secret: str
    secure_connection_bundle: FilePath = Field(default=Path("./secure-connect-identifi.zip"))


class NonAstraCassandra(BaseModel):
    hosts: list[str]
    keyspace: str
    protocol_version: PositiveInt = 3


class Cookies(BaseModel):
    https_only: bool = True
    domain: str | None = None


class CORS(BaseModel):
    origins: list[AnyUrl] = Field(default_factory=list)
    origins_regex: str | None = None
    allow_credentials: bool = False


class DB(BaseModel):
    # line given below will try to build object of AstraCassandra
    # if that is not possible than it will proceed with
    # NonAstraCassandra
    cassandra: AstraCassandra | NonAstraCassandra


class Kafka(BaseModel):
    topics: Topics
    producer: KafkaProduce
    schema_registry: KafkaSchemaRegistry


class KafkaProduce(BaseModel):
    config: dict[str, Any]


class KafkaSchemaRegistry(BaseModel):
    config: dict[str, Any]


class SameSiteExpTime(BaseModel):
    access_token: PositiveInt = 30 * 60 # 30 min
    refresh_token: PositiveInt = 24 * 60 * 60 # 24 hours


class Topics(BaseModel):
    draft_user: str = Field(default="draft_user", pattern="^[A-Za-z_][A-Za-z_0-9]*$")


class OIDCExpTime(SameSiteExpTime):
    authcode: PositiveInt = 2 * 60 # 2 min
    id_token: PositiveInt = 2 * 60 # 2 min


class JWEAlgorithms(BaseModel):
    """
    supported algorithms as on:
    https://python-jose.readthedocs.io/en/latest/jwe/index.html

    [References from python-jose implementation (as of 18 Jan 2024)]:
    https://github.com/mpdavis/python-jose/blob/master/jose/jwe.py
    https://github.com/mpdavis/python-jose/blob/4b0701b46a8d00988afcc5168c2b3a1fd60d15d8/jose/constants.py#L70
    """
    key_management: Literal["dir", "RSA1_5", "RSA_OAEP", "RSA_OAEP_256", "A128KW", "A192KW", "A256KW"]
    encryption: Literal["A128CBC_HS256", "A192CBC_HS384", "A256CBC_HS512", "A128GCM", "A192GCM", "A256GCM"]


class JWE(BaseModel):
    algorithms: JWEAlgorithms
    secret_key: str


class JWTKeys(BaseModel):
    private_key: str
    public_key: str


class JWT(BaseModel):
    """
    supported algorithms as per (since in python-jose JWT PositiveInternally uses JWS to sign JWT tokens):
    https://python-jose.readthedocs.io/en/latest/jws/index.html    

    """
    signing_algorithm: Literal["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
    keys: JWTKeys


class OIDC(BaseModel):
    exp_time: OIDCExpTime
    jwe: JWE
    jwt: JWT


class SameSite(BaseModel):
    exp_time: SameSiteExpTime
    jwt: JWT




class Config(BaseSettings):
    model_config = SettingsConfigDict(yaml_file="auth-config.yaml")


    cookies: Cookies
    cors: CORS
    db: DB
    kafka: Kafka
    oidc: OIDC
    same_site: SameSite

    issuer: HttpUrl
    login_endpoint: str = "/login"
    client_secret_size: PositiveInt = Field(32, alias="max_secret_size_in_bytes") # (in bytes)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
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
    