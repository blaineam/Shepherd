# Optional packaging: runs the static Shepherd binary under Docker's restart policy.
# Build context must contain the `shepherd` binary (a release download or `make build`).
FROM alpine:3
RUN apk add --no-cache ca-certificates tzdata
COPY shepherd /usr/local/bin/shepherd
ENTRYPOINT ["/usr/local/bin/shepherd"]
CMD ["-config", "/etc/shepherd/shepherd.toml"]
