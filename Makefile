build-swift: setup-apple-targets code-gen-swift build-apple-targets combine-swift-binaries setup-xcframework

setup-apple-targets:
	rustup target add aarch64-apple-ios x86_64-apple-ios
	rustup target add aarch64-apple-ios-sim
	rustup target add aarch64-apple-darwin x86_64-apple-darwin

setup-android-targets:
	rustup target add x86_64-linux-android aarch64-linux-android armv7-linux-androideabi i686-linux-android

setup-jvm-targets:
	rustup target add x86_64-apple-darwin aarch64-apple-darwin

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

# Set Android build variables.

# Override this in your environment.
NDK_VERSION ?= 25.2.9519653
ndk_llvm := $(ANDROID_HOME)/ndk/$(NDK_VERSION)/toolchains/llvm/prebuilt/darwin-x86_64/bin
export CFLAGS = "-D__ANDROID_MIN_SDK_VERSION__=24"
export AR = $(ndk_llvm)/llvm-ar
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = $(ndk_llvm)/aarch64-linux-android24-clang
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER = $(ndk_llvm)/x86_64-linux-android24-clang
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER = $(ndk_llvm)/armv7a-linux-androideabi24-clang
export CC = $(ndk_llvm)/$(android_abi)24-clang

build-android-arm64: android_abi = aarch64-linux-android
build-android-arm64:
	cargo build --profile release-smaller --target=$(android_abi)

build-android-x86: android_abi = x86_64-linux-android
build-android-x86:
	cargo build --profile release-smaller --target=$(android_abi)

build-android-arm7: android_abi = armv7a-linux-androideabi
build-android-arm7:
	cargo build --profile release-smaller --target=armv7-linux-androideabi

copy-android-libs:
	mkdir -p lightspark-crypto-kotlin/jniLibs/android/arm64-v8a
	mkdir -p lightspark-crypto-kotlin/jniLibs/android/armeabi-v7a
	mkdir -p lightspark-crypto-kotlin/jniLibs/android/x86_64
	cp -r target/aarch64-linux-android/release-smaller/liblightspark_crypto.so lightspark-crypto-kotlin/jniLibs/android/arm64-v8a/libuniffi_lightspark_crypto.so
	cp -r target/armv7-linux-androideabi/release-smaller/liblightspark_crypto.so lightspark-crypto-kotlin/jniLibs/android/armeabi-v7a/libuniffi_lightspark_crypto.so
	cp -r target/x86_64-linux-android/release-smaller/liblightspark_crypto.so lightspark-crypto-kotlin/jniLibs/android/x86_64/libuniffi_lightspark_crypto.so

build-android: setup-android-targets build-android-arm64 build-android-x86 build-android-arm7 copy-android-libs

build-jvm-targets:
	cargo build --profile release-smaller --target aarch64-apple-darwin
	cargo build --profile release-smaller --target x86_64-apple-darwin

copy-jvm-libs:
	mkdir -p lightspark-crypto-kotlin/jniLibs/jvm/darwin-aarch64
	mkdir -p lightspark-crypto-kotlin/jniLibs/jvm/darwin-x86-64
	cp -r target/aarch64-apple-darwin/release-smaller/liblightspark_crypto.dylib lightspark-crypto-kotlin/jniLibs/jvm/darwin-aarch64/libuniffi_lightspark_crypto.dylib
	cp -r target/x86_64-apple-darwin/release-smaller/liblightspark_crypto.dylib lightspark-crypto-kotlin/jniLibs/jvm/darwin-x86-64/libuniffi_lightspark_crypto.dylib

build-jvm: setup-jvm-targets build-jvm-targets copy-jvm-libs
