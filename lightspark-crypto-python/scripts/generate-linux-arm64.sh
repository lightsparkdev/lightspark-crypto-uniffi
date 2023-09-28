#!/usr/bin/env bash

set -euo pipefail
python --version
pip install -r requirements.txt

echo "Generating python file..."
cd ..
cargo run --bin uniffi-bindgen generate src/lightspark_crypto.udl --language python --out-dir lightspark-crypto-python/src/lightspark_crypto/ --no-format

echo "Generating native binaries..."
docker buildx build -f build.Dockerfile --platform linux/arm64 -o docker-out .

echo "Copying linux binary..."
cp docker-out/target/aarch64-unknown-linux-gnu/release-smaller/liblightspark_crypto.so lightspark-crypto-python/src/lightspark_crypto/libuniffi_lightspark_crypto.so

echo "All done!"
