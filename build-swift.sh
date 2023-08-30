rustup target add aarch64-apple-ios x86_64-apple-ios
rustup target add aarch64-apple-ios-sim
rustup target add aarch64-apple-darwin x86_64-apple-darwin


cargo run --bin uniffi-bindgen generate src/lightspark_crypto.udl --language swift --out-dir lightspark-crypto-swift

cargo build --profile release-smaller --target x86_64-apple-darwin
cargo build --profile release-smaller --target aarch64-apple-darwin
cargo build --profile release-smaller --target x86_64-apple-ios
cargo build --profile release-smaller --target aarch64-apple-ios
cargo build --profile release-smaller --target aarch64-apple-ios-sim

mkdir -p target/lipo-ios-sim/release-smaller
lipo target/aarch64-apple-ios-sim/release-smaller/liblightspark_crypto.a target/x86_64-apple-ios/release-smaller/liblightspark_crypto.a -create -output target/lipo-ios-sim/release-smaller/liblightspark_crypto.a
mkdir -p target/lipo-macos/release-smaller
lipo target/aarch64-apple-darwin/release-smaller/liblightspark_crypto.a target/x86_64-apple-darwin/release-smaller/liblightspark_crypto.a -create -output target/lipo-macos/release-smaller/liblightspark_crypto.a

cp lightspark-crypto-swift/lightspark_cryptoFFI.h lightspark-crypto-swift/lightspark_cryptoFFI.xcframework/ios-arm64/lightspark_cryptoFFI.framework/Headers/lightspark_cryptoFFI.h
cp lightspark-crypto-swift/lightspark_cryptoFFI.h lightspark-crypto-swift/lightspark_cryptoFFI.xcframework/ios-arm64_x86_64-simulator/lightspark_cryptoFFI.framework/Headers/lightspark_cryptoFFI.h
cp lightspark-crypto-swift/lightspark_cryptoFFI.h lightspark-crypto-swift/lightspark_cryptoFFI.xcframework/macos-arm64_x86_64/lightspark_cryptoFFI.framework/Headers/lightspark_cryptoFFI.h
cp target/aarch64-apple-ios/release-smaller/liblightspark_crypto.a lightspark-crypto-swift/lightspark_cryptoFFI.xcframework/ios-arm64/lightspark_cryptoFFI.framework/lightspark_cryptoFFI
cp target/lipo-ios-sim/release-smaller/liblightspark_crypto.a lightspark-crypto-swift/lightspark_cryptoFFI.xcframework/ios-arm64_x86_64-simulator/lightspark_cryptoFFI.framework/lightspark_cryptoFFI
cp target/lipo-macos/release-smaller/liblightspark_crypto.a lightspark-crypto-swift/lightspark_cryptoFFI.xcframework/macos-arm64_x86_64/lightspark_cryptoFFI.framework/lightspark_cryptoFFI
