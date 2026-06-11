#!/bin/bash
# Script to prepare the Raspberry Pi for PQTLS
set -e

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

echo "Installing build dependencies..."
sudo apt-get update
sudo apt-get install -y build-essential cmake swig python3-dev libssl-dev git

echo "Building PQ SDK from the included folder..."
cd "$SCRIPT_DIR/pq_sdk"
mkdir -p build
cd build
cmake ..
make -j$(nproc)

echo "PQ SDK Build Complete."
echo "You can now run the gateway from $SCRIPT_DIR/src/python/main.py"

