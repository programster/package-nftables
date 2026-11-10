# An image for testing the package on a specific version of PHP. Used by testing/run-all-php-versions.sh.
# Build with e.g.: docker build --build-arg PHP_VERSION=8.2 -t nftables-php8.2-test testing/php-versions
ARG PHP_VERSION=8.2
FROM php:${PHP_VERSION}-cli

# nft, for the tests that load rulesets into real nftables, and ip (from iproute2), for the network devices the
# flowtable tests use. unshare (from util-linux) is already in the image.
RUN apt-get update -qq > /dev/null && apt-get install -y -qq nftables iproute2 > /dev/null \
    && rm -rf /var/lib/apt/lists/*
