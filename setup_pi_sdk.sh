#!/bin/bash
# Script to prepare the Raspberry Pi for PQTLS
set -e

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

echo "Installing build dependencies..."
sudo apt-get update
sudo apt-get install -y build-essential cmake swig python3-dev libssl-dev git

echo "Preparing PQ SDK..."
# We assume the user clones pq_sdk in the same parent directory as gateway-piqaso
cd "$SCRIPT_DIR/.."
if [ ! -d "pq_sdk" ]; then
    echo "Cloning PQ SDK..."
    git clone https://gitlab.com/piqaso/pq_sdk.git
fi

cd pq_sdk
mkdir -p build
cd build
cmake ..
make -j$(nproc)

echo "PQ SDK Build Complete."
echo "You can now run the gateway from $SCRIPT_DIR/src/python/main.py"

