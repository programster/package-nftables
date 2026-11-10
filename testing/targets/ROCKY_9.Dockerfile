# The Rocky Linux 9 (and AlmaLinux and RHEL 9) target (nft 1.0.9), for testing/run-all-targets.sh. Uses the php:8.2 module stream.
FROM rockylinux/rockylinux:9
RUN dnf -y -q module enable php:8.2 && dnf -y -q install php-cli nftables util-linux iproute > /dev/null && dnf clean all
