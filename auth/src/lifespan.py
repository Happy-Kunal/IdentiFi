from contextlib import asynccontextmanager

from fastapi import FastAPI

from cassandra.cqlengine import connection
from cassandra.cqlengine import models
from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider
from cassandra.io.libevreactor import LibevConnection
from cassandra.policies import ExponentialReconnectionPolicy

from src.config import cfg, AstraCassandra
from src.events import KafkaProducer

__all__ = ["lifespan"]

@asynccontextmanager
async def lifespan(app: FastAPI):
    # startup begins
    if isinstance(cfg.db.cassandra, AstraCassandra):
        cloud_config = {"secure_connect_bundle": str(cfg.db.cassandra.secure_connection_bundle.absolute())}

        cluster = Cluster(
            auth_provider=PlainTextAuthProvider(
                cfg.db.cassandra.client_id, cfg.db.cassandra.client_secret
            ),
            cloud=cloud_config,
            connection_class=LibevConnection,
            reconnection_policy=ExponentialReconnectionPolicy(base_delay=0.5, max_delay=10)
        )
    else:
        cluster = Cluster(
            cfg.db.cassandra.hosts,
            protocol_version=cfg.db.cassandra.protocol_version,
            connection_class=LibevConnection,
            reconnection_policy=ExponentialReconnectionPolicy(base_delay=0.5, max_delay=60)
        )

    session = cluster.connect(keyspace=cfg.db.cassandra.keyspace)

    connection.register_connection(name="identifi_auth_connection", session=session, default=True)
    models.DEFAULT_KEYSPACE = cfg.db.cassandra.keyspace

    # startup ends
    yield # start fastapi application
    # shutdown begins


    connection.unregister_connection("identifi_auth_connection")
    session.shutdown()
    cluster.shutdown()

    KafkaProducer.flush(timeout=10)

    # shutdown ends

