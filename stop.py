#!/usr/bin/env python3

import argparse
import os


ASTRA_COMPOSE_FILE_PATH = "./docker-compose-astra.yaml"
DB_COMPOSE_FILE_PATH = "./docker-compose.db.yaml"
NON_ASTRA_COMPOSE_FILE_PATH = "./docker-compose-astra.yaml"

parser = argparse.ArgumentParser(
    prog="stop",
    description="program to stop deployed docker containers for project identifi",
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


args = parser.parse_args()

provider = args.provider

if not args.astra:
    os.system(command=f"{provider} compose -f {ASTRA_COMPOSE_FILE_PATH} down")
    os.system(command=f"{provider} compose -f {DB_COMPOSE_FILE_PATH} down")
else:
    os.system(command=f"{provider} compose -f {NON_ASTRA_COMPOSE_FILE_PATH} down")

print("Done!")
