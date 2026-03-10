FROM rust:1.85 AS builder
WORKDIR /workspace
COPY . .
RUN cargo build --release -p cyberbox-collector

FROM gcr.io/distroless/cc-debian12 AS runtime
WORKDIR /app
COPY --from=builder /workspace/target/release/cyberbox-collector /usr/local/bin/cyberbox-collector
EXPOSE 514/udp
EXPOSE 601/tcp
CMD ["/usr/local/bin/cyberbox-collector"]
