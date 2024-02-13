import os

from cassandra.cluster import Cluster, Session
from cassandra.cqlengine import connection
from cassandra.cqlengine.models import Model, ModelMetaClass
from cassandra.cqlengine.management import CQLENG_ALLOW_SCHEMA_MANAGEMENT
from cassandra.cqlengine.management import sync_table, create_keyspace_simple
from cassandra.io.libevreactor import LibevConnection

from src.config import cfg
from .syncer_exceptions import MoreThanSingleInstanceException, MoreThanOneSyncCallsException


CASSANDRA_HOSTS = cfg.db.cassandra.hosts
CASSANDRA_KEYSPACE = cfg.db.cassandra.keyspace
CASSANDRA_PROTOCOL_VERSION = cfg.db.cassandra.protocol_version


class CassandraSyncer:
    no_previous_instance = True
    no_previous_sync_calls = True
    
    def __init__(self, session: Session | None = None) -> None:
        if (not CassandraSyncer.no_previous_instance):
            raise MoreThanSingleInstanceException(
                "only 1 instanace of CassandraSyncer is allowed"
            )
        
        self.session = session
        CassandraSyncer.no_previous_instance = False

    def sync(self, models: list[ModelMetaClass]): # in python class is object of its metaclass
        if (not CassandraSyncer.no_previous_sync_calls):
            raise MoreThanOneSyncCallsException("only 1 call to sync allowed")

        self.no_previous_sync_calls = False

        if (self.session):
            session = self.session
        else:
            cluster = Cluster(CASSANDRA_HOSTS, protocol_version=CASSANDRA_PROTOCOL_VERSION, connection_class=LibevConnection)
            session = cluster.connect()
        
        connection.register_connection("CassandraSyncerConnection", session=session)
        
        os.environ[CQLENG_ALLOW_SCHEMA_MANAGEMENT] = "True"
        
        create_keyspace_simple(
            CASSANDRA_KEYSPACE,
            connections=["CassandraSyncerConnection"],
            replication_factor=min(3, len(CASSANDRA_HOSTS))
        )
        session.set_keyspace(CASSANDRA_KEYSPACE)

        
        for model in models:
            sync_table(model, keyspaces=[CASSANDRA_KEYSPACE], connections=["CassandraSyncerConnection"])
            
            # constructing SASI index to support searching on text field with pattern matching
            # https://cassandra.apache.org/doc/stable/cassandra/cql/SASI.html
            if (hasattr(model, "__cassandra_syncer_create_SASI_index_on__")):
                for column in model.__cassandra_syncer_create_SASI_index_on__:
                    table_name = model.__table_name__ or model.__name__ # https://stackoverflow.com/a/54010214
                    session.execute(
                        f"""
                            CREATE CUSTOM INDEX IF NOT EXISTS {table_name}_{column}_sasi_index
                            ON {table_name} ({column})
                            USING 'org.apache.cassandra.index.sasi.SASIIndex'
                            WITH OPTIONS = {{
                                'analyzer_class': 'org.apache.cassandra.index.sasi.analyzer.NonTokenizingAnalyzer',
                                'case_sensitive': 'false',
                                'mode': 'CONTAINS'
                            }};
                        """
                    )

        os.environ[CQLENG_ALLOW_SCHEMA_MANAGEMENT] = ""


        if (not self.session):
            connection.unregister_connection("CassandraSyncerConnection")
            session.shutdown()
            cluster.shutdown()


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