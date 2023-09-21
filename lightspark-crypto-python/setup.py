from setuptools import setup

setup(
    name="lightspark_crypto_python",
    version="0.1.0",
    description="The Python language bindings for lightspark crypto operations",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    include_package_data = True,
    zip_safe=False,
    packages=["lightspark_crypto"],
    package_dir={"lightspark_crypto": "./src/lightspark_crypto"},
    url="https://github.com/lightsparkdev/lightspark-crypto-uniffi",
    author="Lightspark Group, Inc. <info@lightspark.com>",
    license="Apache 2.0",
    has_ext_modules=lambda: True,
)
