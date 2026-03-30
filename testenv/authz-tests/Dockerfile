FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        jq \
    && rm -rf /var/lib/apt/lists/*
