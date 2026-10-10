ARG RUST_IMAGE=docker.io/library/rust:1.90-bookworm
FROM ${RUST_IMAGE} AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
COPY src ./src
RUN cargo build --release --locked

FROM docker.io/library/debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/are-immutable-ledger /usr/local/bin/are-immutable-ledger
USER 65532:65532
EXPOSE 9092 8080 8083
ENTRYPOINT ["/usr/local/bin/are-immutable-ledger"]
