.PHONY: build test cover check cross run hooks generate-bpf test-xdp

build:
	CGO_ENABLED=0 go build -trimpath -o bin/shepherd ./cmd/shepherd

test:
	go test -race -count=1 ./...

cover:
	scripts/coverage

# Everything CI runs, locally.
check:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	go vet ./...
	scripts/coverage
	node --test internal/portal/web/test/
	scripts/test-leakcheck
	scripts/leakcheck --all

cross:
	scripts/build-release "$$(cat VERSION)-dev"

run: build
	bin/shepherd -config shepherd.toml

hooks:
	scripts/install-hooks

# Rebuild the XDP relay program (internal/intercept/bpf/xdp_relay.c) into
# the committed, embedded objects. Needs a clang with the BPF backend and
# llvm-strip: Homebrew's llvm on macOS (not Apple's clang), or any distro
# clang on Linux. Only maintainers who change the .c file run this; a plain
# `go build` uses the committed objects and needs no clang.
# bpf2go is invoked directly rather than through `go generate`, which would
# silently do nothing here: the //go:generate line lives in xdp_linux.go, and
# on a non-Linux host `go generate` skips that file for failing its build
# constraint -- printing no error and leaving the committed objects stale,
# which is exactly how a verifier fix once got lost. GOOS stays native on
# purpose: setting GOOS=linux would cross-compile bpf2go itself and fail to
# exec. clang cross-compiles the BPF object regardless of the host.
generate-bpf:
	cd internal/intercept && PATH="/opt/homebrew/opt/llvm/bin:$$PATH" \
		go tool bpf2go -target bpfel,bpfeb -go-package intercept -tags linux \
		xdp bpf/xdp_relay.c -- -I bpf/include -Wall -Werror
	@git diff --stat -- internal/intercept/xdp_bpfe*.o | tail -1 | grep -q . \
		&& echo "objects changed: commit internal/intercept/xdp_bpfe*.o" \
		|| echo "objects unchanged"

# Run the XDP program through a real kernel's verifier and BPF_PROG_TEST_RUN.
# Needs Docker (the program loads inside a privileged Linux container); the
# tests skip, not fail, under a plain unprivileged `make test`.
test-xdp:
	GOOS=linux CGO_ENABLED=0 go test -c -o bin/intercept-linux.test ./internal/intercept/
	docker build -q -t shepherd-xdp-test scripts/xdp-test >/dev/null
	docker run --rm --privileged -v "$$(pwd)/bin:/t" -w /t shepherd-xdp-test ./intercept-linux.test -test.v
