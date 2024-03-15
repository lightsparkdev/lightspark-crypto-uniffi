build-swift: setup-apple-targets code-gen-swift build-apple-targets combine-swift-binaries setup-xcframework

setup-apple-targets:
	rustup target add aarch64-apple-ios x86_64-apple-ios
	rustup target add aarch64-apple-ios-sim
	rustup target add aarch64-apple-darwin x86_64-apple-darwin

setup-android-targets:
	rustup target add x86_64-linux-android aarch64-linux-android armv7-linux-androideabi i686-linux-android

setup-go-targets:
	rustup target add x86_64-apple-darwin aarch64-apple-darwin 

setup-jvm-targets:
	rustup target add x86_64-apple-darwin aarch64-apple-darwin

code-gen-swift:
	cargo run --bin uniffi-bindgen generate src/lightspark_crypto.udl --language swift --out-dir lightspark-crypto-swift

code-gen-kotlin:
	cargo run --bin uniffi-bindgen generate src/lightspark_crypto.udl --language kotlin --out-dir lightspark-crypto-kotlin
	sed -i '' 's/package uniffi.lightspark_crypto/package com.lightspark.sdk.crypto.internal/g' lightspark-crypto-kotlin/uniffi/lightspark_crypto/lightspark_crypto.kt

build-darwin-amd64:
	# FIXME(mhr): This currently doesn't work because of the compiler flags defined below for Android, so just noop. If you comment out the CC= line instead, this will work.
	# cargo build --profile release-smaller --target x86_64-apple-darwin

build-darwin-arm64:
	# FIXME(mhr): This currently doesn't work because of the compiler flags defined below for Android, so just noop. If you comment out the CC= line instead, this will work.
	# cargo build --profile release-smaller --target aarch64-apple-darwin

code-gen-go:
	mkdir -p lightspark-crypto-go/internal
	cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.2.1+v0.25.0
	uniffi-bindgen-go src/lightspark_crypto.udl --out-dir lightspark-crypto-go
	mv lightspark-crypto-go/lightspark_crypto/* lightspark-crypto-go/internal
	sed -i '' 's/package lightspark_crypto/package internal/g' lightspark-crypto-go/internal/lightspark_crypto.go
	rm -rf lightspark-crypto-go/uniffi

build-apple-targets: build-darwin-amd64 build-darwin-arm64
	cargo build --profile release-smaller --target x86_64-apple-ios
	cargo build --profile release-smaller --target aarch64-apple-ios
	cargo build --profile release-smaller --target aarch64-apple-ios-sim

combine-swift-binaries: build-apple-targets
	mkdir -p target/lipo-ios-sim/release-smaller
	lipo target/aarch64-apple-ios-sim/release-smaller/liblightspark_crypto.a target/x86_64-apple-ios/release-smaller/liblightspark_crypto.a -create -output target/lipo-ios-sim/release-smaller/liblightspark_crypto.a
	mkdir -p target/lipo-macos/release-smaller
	lipo target/aarch64-apple-darwin/release-smaller/liblightspark_crypto.a target/x86_64-apple-darwin/release-smaller/liblightspark_crypto.a -create -output target/lipo-macos/release-smaller/liblightspark_crypto.a

setup-xcframework: combine-swift-binaries
	cp lightspark-crypto-swift/lightspark_cryptoFFI.h lightspark-crypto-swift/lightspark_cryptoFFI.xcframework/ios-arm64/lightspark_cryptoFFI.framework/Headers/lightspark_cryptoFFI.h
	cp lightspark-crypto-swift/lightspark_cryptoFFI.h lightspark-crypto-swift/lightspark_cryptoFFI.xcframework/ios-arm64_x86_64-simulator/lightspark_cryptoFFI.framework/Headers/lightspark_cryptoFFI.h
	cp lightspark-crypto-swift/lightspark_cryptoFFI.h lightspark-crypto-swift/lightspark_cryptoFFI.xcframework/macos-arm64_x86_64/lightspark_cryptoFFI.framework/Headers/lightspark_cryptoFFI.h
	cp target/aarch64-apple-ios/release-smaller/liblightspark_crypto.a lightspark-crypto-swift/lightspark_cryptoFFI.xcframework/ios-arm64/lightspark_cryptoFFI.framework/lightspark_cryptoFFI
	cp target/lipo-ios-sim/release-smaller/liblightspark_crypto.a lightspark-crypto-swift/lightspark_cryptoFFI.xcframework/ios-arm64_x86_64-simulator/lightspark_cryptoFFI.framework/lightspark_cryptoFFI
	cp target/lipo-macos/release-smaller/liblightspark_crypto.a lightspark-crypto-swift/lightspark_cryptoFFI.xcframework/macos-arm64_x86_64/lightspark_cryptoFFI.framework/lightspark_cryptoFFI

build-linux-amd64-static:
	docker buildx build -f build.Dockerfile --platform linux/amd64 -o docker-out .

build-linux-arm64-static:
	docker buildx build -f build.Dockerfile --platform linux/arm64 -o docker-out .

build-linux-amd64-shared:
	docker buildx build -f build.Dockerfile --build-arg CDYLIB=true --platform linux/amd64 -o docker-out .

build-linux-arm64-shared:
	docker buildx build -f build.Dockerfile  --build-arg CDYLIB=true --platform linux/arm64 -o docker-out .

go-libs: build-darwin-amd64 build-darwin-arm64 build-linux-amd64-static build-linux-arm64-static
	mkdir -p lightspark-crypto-go/libs/darwin/amd64
	mkdir -p lightspark-crypto-go/libs/darwin/arm64
	mkdir -p lightspark-crypto-go/libs/linux/amd64
	mkdir -p lightspark-crypto-go/libs/linux/arm64
	cp target/x86_64-apple-darwin/release-smaller/liblightspark_crypto.a lightspark-crypto-go/libs/darwin/amd64
	cp target/aarch64-apple-darwin/release-smaller/liblightspark_crypto.a lightspark-crypto-go/libs/darwin/arm64
	cp docker-out/target/x86_64-unknown-linux-gnu/release-smaller/liblightspark_crypto.a lightspark-crypto-go/libs/linux/amd64
	cp docker-out/target/aarch64-unknown-linux-gnu/release-smaller/liblightspark_crypto.a lightspark-crypto-go/libs/linux/arm64

build-go: setup-go-targets code-gen-go go-libs

# Set Android build variables.

# Override this in your environment.
NDK_VERSION ?= 25.2.9519653
ndk_llvm := $(ANDROID_HOME)/ndk/$(NDK_VERSION)/toolchains/llvm/prebuilt/darwin-x86_64/bin
export CFLAGS = -D__ANDROID_MIN_SDK_VERSION__=24
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

android-libs: build-android-arm64 build-android-x86 build-android-arm7
	mkdir -p lightspark-crypto-kotlin/jniLibs/android/arm64-v8a
	mkdir -p lightspark-crypto-kotlin/jniLibs/android/armeabi-v7a
	mkdir -p lightspark-crypto-kotlin/jniLibs/android/x86_64
	cp -r target/aarch64-linux-android/release-smaller/liblightspark_crypto.so lightspark-crypto-kotlin/jniLibs/android/arm64-v8a/libuniffi_lightspark_crypto.so
	cp -r target/armv7-linux-androideabi/release-smaller/liblightspark_crypto.so lightspark-crypto-kotlin/jniLibs/android/armeabi-v7a/libuniffi_lightspark_crypto.so
	cp -r target/x86_64-linux-android/release-smaller/liblightspark_crypto.so lightspark-crypto-kotlin/jniLibs/android/x86_64/libuniffi_lightspark_crypto.so

build-android: setup-android-targets code-gen-kotlin android-libs

build-jvm-targets: setup-jvm-targets build-darwin-amd64 build-darwin-arm64 build-linux-amd64-shared build-linux-arm64-shared

jvm-libs: build-jvm-targets
	mkdir -p lightspark-crypto-kotlin/jniLibs/jvm/darwin-aarch64
	mkdir -p lightspark-crypto-kotlin/jniLibs/jvm/darwin-x86-64
	mkdir -p lightspark-crypto-kotlin/jniLibs/jvm/linux-x86-64
	mkdir -p lightspark-crypto-kotlin/jniLibs/jvm/linux-aarch64
	cp -r target/aarch64-apple-darwin/release-smaller/liblightspark_crypto.dylib lightspark-crypto-kotlin/jniLibs/jvm/darwin-aarch64/libuniffi_lightspark_crypto.dylib
	cp -r target/x86_64-apple-darwin/release-smaller/liblightspark_crypto.dylib lightspark-crypto-kotlin/jniLibs/jvm/darwin-x86-64/libuniffi_lightspark_crypto.dylib
	cp -r docker-out/target/x86_64-unknown-linux-gnu/release-smaller/liblightspark_crypto.so lightspark-crypto-kotlin/jniLibs/jvm/linux-x86-64/libuniffi_lightspark_crypto.so
	cp -r docker-out/target/aarch64-unknown-linux-gnu/release-smaller/liblightspark_crypto.so lightspark-crypto-kotlin/jniLibs/jvm/linux-aarch64/libuniffi_lightspark_crypto.so

build-jvm: setup-jvm-targets jvm-libs

build-wasm:
	wasm-pack build --profile release-smaller --scope lightsparkdev
