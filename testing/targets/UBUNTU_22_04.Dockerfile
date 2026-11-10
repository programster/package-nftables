# The Ubuntu 22.04 target (nft 1.0.2), for testing/run-all-targets.sh. Ubuntu 22.04's own PHP (8.1) is too old, so PHP 8.2 comes from the ondrej/php PPA.
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq software-properties-common > /dev/null \
    && add-apt-repository -y ppa:ondrej/php > /dev/null \
    && apt-get update -qq && apt-get install -y -qq php8.2-cli nftables iproute2 > /dev/null && rm -rf /var/lib/apt/lists/*
