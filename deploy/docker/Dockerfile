# Optional packaging: runs the static Shepherd binary under Docker's restart policy.
# Build context must contain the `shepherd` binary (a release download or `make build`).
FROM alpine:3
# nftables is only needed by DHCP mode (docs/DHCP.md), which is off by
# default: Shepherd owns one nftables table and applies it by running nft.
# Without the package DHCP mode reports itself unavailable in the portal and
# everything else runs untouched.
RUN apk add --no-cache ca-certificates tzdata nftables
COPY shepherd /usr/local/bin/shepherd
ENTRYPOINT ["/usr/local/bin/shepherd"]
CMD ["-config", "/etc/shepherd/shepherd.toml"]
