Please follow the below steps to release a new version of the crypto library.

# Python

Python build and release is setup on Github action.

## Step 1: Bump python lib version
In `python/lightspark_crypto/__init__.py`, bump the version number.

## Step 2: Run `Publish to PyPI` workflow
https://github.com/lightsparkdev/lightspark-crypto-uniffi/actions/workflows/publish_python.yml

# Go

Go library needs to be built and released manually following the below steps.

## Step 1: Build

Run the following command to build the go library.

```bash
$ make build-go
```

Then create a PR and commit the changes.

## Step 2: Release

Create a release tag and make a release on Github.

## Step 3: Publish to Go

Run the following command to publish the go library.

```bash
$ GOPROXY=proxy.golang.org go list -m github.com/lightsparkdev/lightspark-crypto-uniffi/lightspark-crypto-go@[version]
```

# Kotlin

TODO

# Swift

Run `Release` github action workflow to release the swift library.

