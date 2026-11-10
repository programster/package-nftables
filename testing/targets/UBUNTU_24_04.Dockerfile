# The Ubuntu 24.04 target (nft 1.0.9), for testing/run-all-targets.sh. With its own PHP (8.3).
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq php-cli nftables iproute2 > /dev/null && rm -rf /var/lib/apt/lists/*
