#!/bin/bash
set -e

echo "Starting Deployment..."

echo "Pulling from Git..."
git pull origin main

echo "Building Go Binary..."
go build -o geararea-api ./srv/geararea/api

echo "Restarting Service..."
sudo systemctl restart geararea

echo "Deployment Successful!"