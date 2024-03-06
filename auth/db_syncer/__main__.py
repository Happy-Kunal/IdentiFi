import sys
import argparse
import getpass

from cassandra.auth import PlainTextAuthProvider
from cassandra.cluster import Cluster
from cassandra.io.libevreactor import LibevConnection
from cassandra.policies import ExponentialReconnectionPolicy

from src.crud import models_to_be_synced

from .syncer import AstraDBKeyspaceEngine, CassandraSyncer, NonAstraDBKeyspaceEngine



def parse_args() -> dict:
    parser = argparse.ArgumentParser(
        "db_syncer",
        description="""command line utility to create necessary keyspaces and tables for project identifi."""
    )

    parser.add_argument("-k", "--keyspace", required=True)

    subparsers = parser.add_subparsers(
        help="syncing with cassandra hosted on astradb or non-astradb"
    )

    astra_db_parser = subparsers.add_parser(
        name="astra",
        description="sync tables and keyspace on database hosted on astradb",
    )

    astra_db_parser.add_argument(
        "-s",
        "--secure-connection-bundle",
        required=True,
        dest="secure_connection_bundle",
        type=str,
    )
    astra_db_parser.add_argument("-c", "--client-id", required=True, dest="client_id")
    astra_db_parser.add_argument("-d", "--db-id", dest="db_id", required=True, type=str)

    non_astra_db_parser = subparsers.add_parser(
        name="nastra",
        description="sync tables and keyspace on database not hosted on astradb",
    )

    non_astra_db_parser.add_argument(
        "-host",
        "--host",
        const=None,
        required=True,
        dest="hosts",
        action="append",
        type=str,
    )

    non_astra_db_parser.add_argument(
        "-p", "--protocol-version", required=True, dest="protocol_version", type=int
    )

    non_astra_db_parser.add_argument(
        "-r", "--replication_factor", required=True, dest="replication_factor", type=int
    )

    ans = parser.parse_args().__dict__.copy()

    if "secure_connection_bundle" in ans:
        ans.update(client_secret=getpass.getpass("enter client_secret: "))
        ans.update(token=getpass.getpass("enter client_token: "))

    return ans


def main():
    args = parse_args()

    confirmation_received = False
    for _ in range(3):
        confirmation_string = "mutate database"
        confirmation = input(f"type [{confirmation_string}] to proceed: ").lower()

        if confirmation == confirmation_string:
            confirmation_received = True
            break

    if not confirmation_received:
        print("Aborting...")
        sys.exit(1)
    elif "secure_connection_bundle" in args:
        cloud_config = {"secure_connect_bundle": args["secure_connection_bundle"]}
        cluster = Cluster(
            auth_provider=PlainTextAuthProvider(
                args["client_id"], args["client_secret"]
            ),
            cloud=cloud_config,
            connection_class=LibevConnection,
            reconnection_policy=ExponentialReconnectionPolicy(base_delay=0.5, max_delay=10)
        )
        keyspace_engine = AstraDBKeyspaceEngine(
            database_id=args["db_id"], token=args["token"]
        )
    else:
        cluster = Cluster(
            args["hosts"],
            protocol_version=args["protocol_version"],
            connection_class=LibevConnection,
            reconnection_policy=ExponentialReconnectionPolicy(base_delay=0.5, max_delay=60)
        )
        keyspace_engine = NonAstraDBKeyspaceEngine(replication_factor=args["replication_factor"])

    session = cluster.connect()

    syncer = CassandraSyncer(
        args["keyspace"], session=session, keyspace_engine=keyspace_engine
    )
    syncer.sync(models_to_be_synced)

    session.shutdown()
    cluster.shutdown()
    
    print("Done!")


if __name__ == "__main__":
    main()
