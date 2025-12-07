#!/bin/bash
set -e

echo "Restarting Service..."
sudo systemctl restart geararea

echo "Deployment Successful!"
