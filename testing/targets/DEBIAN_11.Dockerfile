# The Debian 11 target (nft 0.9.8), for testing/run-all-targets.sh. Debian 11's own PHP (7.4) is too old, so this is its nft with PHP 8.2.
# Debian 11's support has ended, and its security repository no longer has every package it lists, so it's left out. These are throwaway test containers, and nft is the same version without it.
FROM php:8.2-cli-bullseye
RUN sed -i "/debian-security/d" /etc/apt/sources.list \
    && apt-get update -qq && apt-get install -y -qq nftables iproute2 > /dev/null && rm -rf /var/lib/apt/lists/*
