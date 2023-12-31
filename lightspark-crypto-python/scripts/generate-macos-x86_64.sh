#!/usr/bin/env bash

set -euo pipefail
python3 --version
pip install --user -r requirements.txt

echo "Generating python file..."
cd ..
cargo run --bin uniffi-bindgen generate src/lightspark_crypto.udl --language python --out-dir lightspark-crypto-python/src/lightspark_crypto/ --no-format

echo "Generating native binaries..."
rustup target add x86_64-apple-darwin
cargo build --profile release-smaller --target x86_64-apple-darwin

echo "Copying libraries dylib..."
cp target/x86_64-apple-darwin/release-smaller/liblightspark_crypto.dylib lightspark-crypto-python/src/lightspark_crypto/libuniffi_lightspark_crypto.dylib

echo "All done!"

