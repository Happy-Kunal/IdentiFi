#!/bin/bash

echo "starting database..."
podman compose -f ./docker-compose.db.yaml up -d

echo "waiting for database to start accepting connections (60 sec approx.)..."
sleep 20
echo "waiting for database to start accepting connections (40 sec approx.)..."
sleep 20
echo "waiting for database to start accepting connections (20 sec approx.)..."
sleep 20

echo "starting all other containers..."
podman compose up -d

echo "COMPLETE!"
