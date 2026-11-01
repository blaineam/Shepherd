# Image for `make test-xdp`: a Linux userland with iproute2, so the veth
# end-to-end test can run; the test binary itself is built on the host.
FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y -qq iproute2 >/dev/null && rm -rf /var/lib/apt/lists/*
