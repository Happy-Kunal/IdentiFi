import os
from typing import List

from cassandra.cluster import Cluster
from cassandra.cqlengine import connection
from cassandra.cqlengine.models import Model
from cassandra.cqlengine.management import CQLENG_ALLOW_SCHEMA_MANAGEMENT
from cassandra.cqlengine.management import sync_table, create_keyspace_simple

from src.config import cfg
from .syncer_exceptions import MoreThanSingleInstanceException, MoreThanOneSyncCallsException


CASSANDRA_HOSTS = cfg.db.cassandra.hosts
CASSANDRA_KEYSPACE = cfg.db.cassandra.keyspace
CASSANDRA_PROTOCOL_VERSION = cfg.db.cassandra.protocol_version


class CassandraSyncer:
    no_previous_instance = True
    no_previous_sync_calls = True
    
    def __init__(self) -> None:
        if (not self.no_previous_instance):
            raise MoreThanSingleInstanceException(
                "only 1 instanace of CassandraSyncer is allowed"
            )
        
        CassandraSyncer.no_previous_instance = False

    def sync(self, models: List[Model]):
        if (not self.no_previous_sync_calls):
            raise MoreThanOneSyncCallsException("only 1 call to sync allowed")

        self.no_previous_sync_calls = False

        cluster = Cluster(CASSANDRA_HOSTS, protocol_version=CASSANDRA_PROTOCOL_VERSION)
        session = cluster.connect()
        connection.register_connection("CassandraSyncerConnection", session=session)
        
        os.environ[CQLENG_ALLOW_SCHEMA_MANAGEMENT] = "True"
        
        create_keyspace_simple(
            CASSANDRA_KEYSPACE,
            connections=["CassandraSyncerConnection"],
            replication_factor=min(3, len(CASSANDRA_HOSTS))
        )
        
        for model in models:
            sync_table(model, keyspaces=[CASSANDRA_KEYSPACE], connections=["CassandraSyncerConnection"])

        os.environ[CQLENG_ALLOW_SCHEMA_MANAGEMENT] = ""

        connection.unregister_connection("CassandraSyncerConnection")
        session.shutdown()
        cluster.shutdown()


if __name__ == "__main__":
    from cassandra.cqlengine import columns

    class Model1(Model):
        id = columns.UUID(primary_key=True)
        name = columns.Text()
    
    class Model2(Model):
        id = columns.UUID(primary_key=True)
        name = columns.Text()

    syncer = CassandraSyncer()
    syncer.sync([Model1, Model2])