build-swift: setup-apple-targets code-gen-swift build-apple-targets combine-swift-binaries setup-xcframework

setup-apple-targets:
	rustup target add aarch64-apple-ios x86_64-apple-ios
	rustup target add aarch64-apple-ios-sim
	rustup target add aarch64-apple-darwin x86_64-apple-darwin

code-gen-swift:
	cargo run --bin uniffi-bindgen generate src/lightspark_crypto.udl --language swift --out-dir lightspark-crypto-swift

code-gen-kotlin:
	cargo run --bin uniffi-bindgen generate src/lightspark_crypto.udl --language kotlin --out-dir lightspark-crypto-kotlin

build-apple-targets:
	cargo build --profile release --target x86_64-apple-darwin
	cargo build --profile release --target aarch64-apple-darwin
	cargo build --profile release --target x86_64-apple-ios
	cargo build --profile release --target aarch64-apple-ios
	cargo build --profile release --target aarch64-apple-ios-sim

combine-swift-binaries:
	mkdir -p target/lipo-ios-sim/release
	lipo target/aarch64-apple-ios-sim/release/liblightspark_crypto.a target/x86_64-apple-ios/release/liblightspark_crypto.a -create -output target/lipo-ios-sim/release/liblightspark_crypto.a
	mkdir -p target/lipo-macos/release
	lipo target/aarch64-apple-darwin/release/liblightspark_crypto.a target/x86_64-apple-darwin/release/liblightspark_crypto.a -create -output target/lipo-macos/release/liblightspark_crypto.a

setup-xcframework:
	cp lightspark-crypto-swift/lightspark_cryptoFFI.h lightspark-crypto-swift/lightspark_cryptoFFI.xcframework/ios-arm64/lightspark_cryptoFFI.framework/Headers/lightspark_cryptoFFI.h
	cp lightspark-crypto-swift/lightspark_cryptoFFI.h lightspark-crypto-swift/lightspark_cryptoFFI.xcframework/ios-arm64_x86_64-simulator/lightspark_cryptoFFI.framework/Headers/lightspark_cryptoFFI.h
	cp lightspark-crypto-swift/lightspark_cryptoFFI.h lightspark-crypto-swift/lightspark_cryptoFFI.xcframework/macos-arm64_x86_64/lightspark_cryptoFFI.framework/Headers/lightspark_cryptoFFI.h
	cp target/aarch64-apple-ios/release/liblightspark_crypto.a lightspark-crypto-swift/lightspark_cryptoFFI.xcframework/ios-arm64/lightspark_cryptoFFI.framework/lightspark_cryptoFFI
	cp target/lipo-ios-sim/release/liblightspark_crypto.a lightspark-crypto-swift/lightspark_cryptoFFI.xcframework/ios-arm64_x86_64-simulator/lightspark_cryptoFFI.framework/lightspark_cryptoFFI
	cp target/lipo-macos/release/liblightspark_crypto.a lightspark-crypto-swift/lightspark_cryptoFFI.xcframework/macos-arm64_x86_64/lightspark_cryptoFFI.framework/lightspark_cryptoFFI