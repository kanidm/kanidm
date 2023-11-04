#!/bin/bash

echo "Tearing down"
docker-compose down -t0
echo "Building up"
docker-compose up -d
echo "LOG TIME!"
docker-compose logs -f
