.PHONY: build test cover check cross run hooks

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
	scripts/test-leakcheck
	scripts/leakcheck --all

cross:
	scripts/build-release "$$(cat VERSION)-dev"

run: build
	bin/shepherd -config shepherd.toml

hooks:
	scripts/install-hooks
