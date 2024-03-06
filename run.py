#!/usr/bin/env python3

import argparse
import os
import time


ASTRA_COMPOSE_FILE_PATH = "./docker-compose-astra.yaml"
DB_COMPOSE_FILE_PATH = "./docker-compose.db.yaml"
NON_ASTRA_COMPOSE_FILE_PATH = "./docker-compose-astra.yaml"
OVERRIDE_COMPOSE_FILE_PATH = "./docker-compose.override.yaml"

parser = argparse.ArgumentParser(
    prog="run",
    description="program to deploy correct docker containers for project identifi",
)

parser.add_argument(
    "-astra",
    "--astra",
    action="store_true",
    dest="astra",
    help="use this flag if using cassandra hosted on astraDB ",
)

parser.add_argument(
    "-p",
    "--provider",
    choices=("docker", "podman"),
    default="docker",
    dest="provider",
    help="whether using podman or docker (default: docker)"
)

parser.add_argument(
    "-d",
    "--detached",
    action="store_const",
    const="-d",
    default="",
    dest="detached_mode",
    help="run containers in detached mode"
)


args = parser.parse_args()

provider = args.provider
detached_mode = args.detached_mode

if not args.astra:
    print("starting database...")
    os.system(command=f"{provider} compose -f {DB_COMPOSE_FILE_PATH} up {detached_mode}")

    for i in range(60, 0, -20):
        print(f"waiting for database to start accepting connections ({i} sec approx.)...")
        time.sleep(20)

    print("starting all other containers...")
    os.system(command=f"{provider} compose -f {ASTRA_COMPOSE_FILE_PATH} -f {OVERRIDE_COMPOSE_FILE_PATH} up {detached_mode} --build")

else:
    os.system(command=f"{provider} compose -f {NON_ASTRA_COMPOSE_FILE_PATH} -f {OVERRIDE_COMPOSE_FILE_PATH} up {detached_mode} --build")



print("Done!")
