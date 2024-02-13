#!/bin/bash

podman compose -f ./docker-compose.yaml down
podman compose -f ./docker-compose.db.yaml down