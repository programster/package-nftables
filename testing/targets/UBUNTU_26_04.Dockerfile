# The Ubuntu 26.04 target (nft 1.1.6), for testing/run-all-targets.sh. With its own PHP.
FROM ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq php-cli nftables iproute2 > /dev/null && rm -rf /var/lib/apt/lists/*
