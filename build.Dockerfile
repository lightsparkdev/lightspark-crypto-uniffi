FROM rust:latest AS build-stage

ARG TARGETOS TARGETARCH
RUN echo "$TARGETARCH" | sed 's,arm,aarch,;s,amd,x86_,' > /tmp/arch

RUN apt-get update && apt-get install -y "gcc-$(tr _ - < /tmp/arch)-linux-gnu"
RUN rustup target add "$(cat /tmp/arch)-unknown-${TARGETOS}-gnu"

WORKDIR /project

COPY Cargo.toml Cargo.lock build.rs uniffi-bindgen.rs ./
COPY src ./src/

RUN cargo build --target "$(cat /tmp/arch)-unknown-${TARGETOS}-gnu" --profile release-smaller

FROM scratch AS export-stage
COPY --from=build-stage /project/target /target