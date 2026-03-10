FROM rust:1.82 AS builder
WORKDIR /workspace
COPY . .
RUN cargo build --release -p cyberbox-worker

FROM gcr.io/distroless/cc-debian12
WORKDIR /app
COPY --from=builder /workspace/target/release/cyberbox-worker /usr/local/bin/cyberbox-worker
COPY config/default.toml /app/config/default.toml
CMD ["/usr/local/bin/cyberbox-worker"]