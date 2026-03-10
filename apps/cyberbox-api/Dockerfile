FROM rust:1.82 AS builder
WORKDIR /workspace
COPY . .
RUN cargo build --release -p cyberbox-api

FROM gcr.io/distroless/cc-debian12
WORKDIR /app
COPY --from=builder /workspace/target/release/cyberbox-api /usr/local/bin/cyberbox-api
COPY config/default.toml /app/config/default.toml
EXPOSE 8080
CMD ["/usr/local/bin/cyberbox-api"]