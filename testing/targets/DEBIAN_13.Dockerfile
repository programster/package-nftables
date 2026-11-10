# The Debian 13 target (nft 1.1.3), for testing/run-all-targets.sh.
FROM php:8.2-cli-trixie
RUN apt-get update -qq && apt-get install -y -qq nftables iproute2 > /dev/null && rm -rf /var/lib/apt/lists/*
