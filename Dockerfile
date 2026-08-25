# syntax=docker/dockerfile:1
# Builds the Proof deployable stack binaries (proof-server + proof-worker).
#
# The build stage compiles the release profile; the runtime stage ships only
# the two binaries plus CA certificates. TLS termination and trusted-proxy
# configuration are deployment prerequisites outside this image.

FROM rust:1.97-bookworm AS build
WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY conformance ./conformance
RUN cargo build --release --locked --bin proof-server --bin proof-worker

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/proof-server /usr/local/bin/proof-server
COPY --from=build /build/target/release/proof-worker /usr/local/bin/proof-worker

ENV PROOF_LISTEN_ADDR=0.0.0.0:8080
EXPOSE 8080

# Liveness uses the public capabilities route; no extra health route exists.
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8080/api/v1/capabilities >/dev/null || exit 1

ENTRYPOINT ["proof-server"]
