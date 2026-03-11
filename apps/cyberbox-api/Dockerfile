FROM lukemathwalker/cargo-chef:latest-rust-1.85 AS chef
WORKDIR /workspace

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /workspace/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json -p cyberbox-api
COPY . .
RUN cargo build --release -p cyberbox-api

FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.title="cyberbox-api" \
      org.opencontainers.image.description="CyberboxSIEM API server" \
      org.opencontainers.image.source="https://github.com/cyberboxsiem/CyberboxSIEM"
WORKDIR /app
COPY --from=builder /workspace/target/release/cyberbox-api /usr/local/bin/cyberbox-api
COPY config/default.toml /app/config/default.toml
EXPOSE 8080
CMD ["/usr/local/bin/cyberbox-api"]
