import secrets
import threading
from typing import Callable
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
from src.crud import CRUDOps

__all__ = ["lifespan"]

@asynccontextmanager
async def lifespan(app: FastAPI):
    # startup begins
    CRUDOps.connect()

    shutdown_event = threading.Event()
    db_hibernation_prevention_thread = threading.Thread(
        target=timeloop,
        kwargs={
            "target": CRUDOps.ping_db,
            "shutdown_event": shutdown_event,
            "max_timeout": cfg.db.max_hibernation_prevention_wait,
            "max_timeout_deviation": cfg.db.max_hibernation_prevention_wait_deviation
        }
    )

    kafka_producer_flush_thread = threading.Thread(
        target=timeloop,
        kwargs={
            "target": lambda: KafkaProducer.poll(timeout=cfg.kafka.producer.poll_timeout),
            "shutdown_event": shutdown_event,
            "max_timeout": cfg.kafka.producer.poll_interval,
            "max_timeout_deviation": 0
        }
    )

    db_hibernation_prevention_thread.start()
    kafka_producer_flush_thread.start()

    # startup ends
    yield # start fastapi application
    # shutdown begins

    shutdown_event.set()

    db_hibernation_prevention_thread.join()
    kafka_producer_flush_thread.join()

    CRUDOps.disconnect()

    KafkaProducer.flush(timeout=cfg.kafka.producer.flush_timeout)

    # shutdown ends


def timeloop(
    target: Callable,
    shutdown_event: threading.Event,
    max_timeout: float | None = None,
    max_timeout_deviation: int = 10
):
    if max_timeout is not None:
        timeout = abs(max_timeout - secrets.randbelow(max_timeout_deviation + 1))
    else:
        timeout = None

    while not shutdown_event.wait(timeout=timeout):
        target()

