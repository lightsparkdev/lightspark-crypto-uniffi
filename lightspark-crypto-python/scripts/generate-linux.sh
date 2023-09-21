#!/usr/bin/env bash

set -euo pipefail
${PYBIN}/python --version
${PYBIN}/pip install -r requirements.txt

echo "Generating python file..."
cd ..
cargo run --bin uniffi-bindgen generate src/lightspark_crypto.udl --language python --out-dir lightspark-crypto-python/src/lightspark_crypto/ --no-format

echo "Generating native binaries..."
cargo build --profile release-smaller

echo "Copying linux binary..."
cp target/release-smaller/liblightspark_crypto.so lightspark-crypto-python/src/lightspark_crypto/libuniffi_lightspark_crypto.so

echo "All done!"
