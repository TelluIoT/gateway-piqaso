#!/bin/bash
# Script to prepare the Raspberry Pi for PQTLS
set -e

echo "Installing build dependencies..."
sudo apt-get update
sudo apt-get install -y build-essential cmake swig python3-dev libssl-dev git

echo "Cloning and building PQ SDK..."
# We assume the user clones the repo to the same path as on the host for consistency
cd ~
if [ ! -d "pq_sdk" ]; then
    git clone https://gitlab.com/piqaso/pq_sdk.git
fi

cd pq_sdk
mkdir -p build
cd build
cmake ..
make -j$(nproc)

echo "Copying gateway-piqaso files..."
# This part would typically be done via scp from the host to the Pi:
# scp -r /c/tellucare/gateway-piqaso pi@raspberrypi.local:~/
