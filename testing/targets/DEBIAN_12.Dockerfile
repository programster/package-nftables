# The Debian 12 target (nft 1.0.6), for testing/run-all-targets.sh.
FROM php:8.2-cli-bookworm
RUN apt-get update -qq && apt-get install -y -qq nftables iproute2 > /dev/null && rm -rf /var/lib/apt/lists/*
