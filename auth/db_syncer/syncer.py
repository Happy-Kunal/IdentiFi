from abc import ABC, abstractmethod
import os
from typing import override

from cassandra.cluster import Session
from cassandra.cqlengine import connection
from cassandra.cqlengine.models import Model, ModelMetaClass
from cassandra.cqlengine.management import CQLENG_ALLOW_SCHEMA_MANAGEMENT
from cassandra.cqlengine.management import sync_table, create_keyspace_simple

import requests

from .syncer_exceptions import MoreThanSingleInstanceException, MoreThanOneSyncCallsException


class KeyspaceEngine(ABC):
    @abstractmethod
    def create(self, keyspace: str, connections: list[str]) -> None:
        raise NotImplementedError
    

class AstraDBKeyspaceEngine(KeyspaceEngine):
    def __init__(self, database_id: str, token: str) -> None:
        self.database_id = database_id
        self.token = token

    @override
    def create(self, keyspace: str, connections: list[str]) -> None:
        req = requests.post(
            f"https://api.astra.datastax.com/v2/databases/{self.database_id}/keyspaces/{keyspace}",
            headers={"Authorization": f"Bearer {self.token}"}
        )

        if (req.status_code != 201):
            raise Exception("couldn't create keyspace")


class NonAstraDBKeyspaceEngine(KeyspaceEngine):
    def __init__(self, replication_factor: int = 3) -> None:
        self.replication_factor = replication_factor

    @override
    def create(self, keyspace: str, connections: list[str]) -> None:
        create_keyspace_simple(
            keyspace,
            connections=connections,
            replication_factor=self.replication_factor
        )



class CassandraSyncer:
    no_previous_instance = True
    no_previous_sync_calls = True
    
    def __init__(self, keyspace: str, session: Session, keyspace_engine: KeyspaceEngine) -> None:
        if (not CassandraSyncer.no_previous_instance):
            raise MoreThanSingleInstanceException(
                "only 1 instanace of CassandraSyncer is allowed"
            )
        
        CassandraSyncer.no_previous_instance = False
        self.keyspace = keyspace
        self.session = session
        self.keyspace_engine = keyspace_engine

    def sync(self, models: list[ModelMetaClass]): # in python class is object of its metaclass
        if (not CassandraSyncer.no_previous_sync_calls):
            raise MoreThanOneSyncCallsException("only 1 call to sync allowed")

        self.no_previous_sync_calls = False
        
        connection.register_connection("CassandraSyncerConnection", session=self.session)
        
        os.environ[CQLENG_ALLOW_SCHEMA_MANAGEMENT] = "True"
        
        
        self.keyspace_engine.create(keyspace=self.keyspace, connections=["CassandraSyncerConnection"])
        self.session.set_keyspace(self.keyspace)

        
        for model in models:
            table_name = model.__table_name__ or model.__name__ # https://stackoverflow.com/a/54010214
            print("creating table: ", table_name)
            sync_table(model, keyspaces=[self.keyspace], connections=["CassandraSyncerConnection"])                

        os.environ[CQLENG_ALLOW_SCHEMA_MANAGEMENT] = ""


if __name__ == "__main__":
    from cassandra.cqlengine import columns

    class Model1(Model):
        id = columns.UUID(primary_key=True)
        name = columns.Text()
    
    class Model2(Model):
        __cassandra_syncer_create_SASI_index_on__ = ["name"]
        
        id = columns.UUID(primary_key=True)
        name = columns.Text()

    syncer = CassandraSyncer()
    syncer.sync([Model1, Model2])
