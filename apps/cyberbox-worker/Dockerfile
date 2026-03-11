FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /workspace

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /workspace/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json -p cyberbox-worker
COPY . .
RUN cargo build --release -p cyberbox-worker

FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.title="cyberbox-worker" \
      org.opencontainers.image.description="CyberboxSIEM background worker — detection, aggregation, correlation" \
      org.opencontainers.image.source="https://github.com/cyberboxsiem/CyberboxSIEM"
WORKDIR /app
COPY --from=builder /workspace/target/release/cyberbox-worker /usr/local/bin/cyberbox-worker
COPY config/default.toml /app/config/default.toml
CMD ["/usr/local/bin/cyberbox-worker"]
