FROM rust:1.88-bookworm AS build
WORKDIR /app
COPY . .
RUN cargo build --release -p license-api
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/license-api /usr/local/bin/license-api
CMD ["license-api"]
