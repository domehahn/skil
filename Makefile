.PHONY: build docker-build docker-smoke test test-linux-isolation test-windows-compile lint fmt vet

GOCACHE ?= /tmp/skil-go-cache
GOWORK ?= off

build:
	GOWORK=$(GOWORK) GOCACHE=$(GOCACHE) go build -trimpath -o bin/skil ./cmd/skil

docker-build:
	docker build -t skil:local .

docker-smoke: docker-build
	docker run --rm skil:local version

test:
	GOWORK=$(GOWORK) GOCACHE=$(GOCACHE) go test -race ./...

test-linux-isolation:
	docker run --rm --privileged -v "$$(pwd):/src:ro" -w /src \
		-e SKIL_REQUIRE_NATIVE_ISOLATION=1 golang:1.24-bookworm \
		bash -c 'apt-get update -qq && apt-get install -y -qq bubblewrap util-linux >/dev/null && go test ./internal/eval -run TestNativeIsolationExecutesAdapterWhenAvailable -v'

test-windows-compile:
	GOWORK=$(GOWORK) GOCACHE=$(GOCACHE) GOOS=windows GOARCH=amd64 \
		go test -c -o /tmp/skil-eval-windows.test.exe ./internal/eval

lint: vet
	test -z "$$(gofmt -l cmd internal pkg tests)"

vet:
	GOWORK=$(GOWORK) GOCACHE=$(GOCACHE) go vet ./...

fmt:
	gofmt -w cmd internal pkg tests
