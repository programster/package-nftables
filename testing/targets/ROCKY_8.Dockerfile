# The Rocky Linux 8 (and AlmaLinux and RHEL 8) target (nft 1.0.4), for testing/run-all-targets.sh. Uses the php:8.2 module stream.
FROM rockylinux/rockylinux:8
RUN dnf -y -q module enable php:8.2 && dnf -y -q install php-cli nftables util-linux iproute findutils > /dev/null && dnf clean all
