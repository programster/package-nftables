# The Rocky Linux 10 (and AlmaLinux and RHEL 10) target (nft 1.1.5), for testing/run-all-targets.sh. With its own PHP (8.3).
FROM rockylinux/rockylinux:10
RUN dnf -y -q install php-cli nftables util-linux iproute findutils > /dev/null && dnf clean all
