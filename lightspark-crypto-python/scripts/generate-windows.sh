#!/usr/bin/env bash

set -euo pipefail
python3 --version
pip install --user -r requirements.txt

echo "Generating python file..."
cd ..
cargo run --bin uniffi-bindgen generate src/lightspark_crypto.udl --language python --out-dir lightspark-crypto-python/src/lightspark_crypto/ --no-format

echo "Generating native binaries..."
rustup target add x86_64-pc-windows-msvc
cargo build --profile release-smaller --target x86_64-pc-windows-msvc

echo "Copying libraries..."
cp target/x86_64-pc-windows-msvc/release-smaller/lightspark_crypto.dll lightspark-crypto-python/src/lightspark_crypto/uniffi_lightspark_crypto.dll

echo "All done!"
