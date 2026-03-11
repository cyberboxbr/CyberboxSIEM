FROM lukemathwalker/cargo-chef:latest-rust-1-bookworm AS chef
WORKDIR /workspace

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /workspace/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json -p cyberbox-collector
COPY . .
RUN cargo build --release -p cyberbox-collector

FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.title="cyberbox-collector" \
      org.opencontainers.image.description="CyberboxSIEM log collector — syslog, GELF, JSON, OTLP, NetFlow" \
      org.opencontainers.image.source="https://github.com/cyberboxsiem/CyberboxSIEM"
WORKDIR /app
COPY --from=builder /workspace/target/release/cyberbox-collector /usr/local/bin/cyberbox-collector
EXPOSE 514/udp
EXPOSE 601/tcp
CMD ["/usr/local/bin/cyberbox-collector"]
