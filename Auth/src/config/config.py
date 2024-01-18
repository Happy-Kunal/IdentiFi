# https://docs.pydantic.dev/latest/concepts/pydantic_settings/

from typing import List, Literal, Any

from pydantic import BaseModel, Field
from pydantic import HttpUrl, PositiveInt

from pydantic_settings import BaseSettings, SettingsConfigDict


class Cassandra(BaseModel):
    hosts: List[str]
    keyspace: str
    protocol_version: PositiveInt = 3


class Cookies(BaseModel):
    https_only: bool = True


class DBSchemas(BaseModel):
    update: bool = False


class DB(BaseModel):
    cassandra: Cassandra
    schemas: DBSchemas


class SameSiteExpTime(BaseModel):
    access_token: PositiveInt = 30 * 60 # 30 min
    refresh_token: PositiveInt = 24 * 60 * 60 # 24 hours


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
    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', env_nested_delimiter=".")


    cookies: Cookies
    db: DB
    oidc: OIDC
    same_site: SameSite

    issuer: HttpUrl
    login_endpoint: str = "/login"
    client_secret_size: PositiveInt = Field(32, alias="max_secret_size_in_bytes") # (in bytes)