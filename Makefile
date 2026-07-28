.PHONY: build test lint fmt vet

GOCACHE ?= /tmp/skil-go-cache
GOWORK ?= off

build:
	GOWORK=$(GOWORK) GOCACHE=$(GOCACHE) go build -trimpath -o bin/skil ./cmd/skil

test:
	GOWORK=$(GOWORK) GOCACHE=$(GOCACHE) go test -race ./...

lint: vet
	test -z "$$(gofmt -l cmd internal pkg)"

vet:
	GOWORK=$(GOWORK) GOCACHE=$(GOCACHE) go vet ./...

fmt:
	gofmt -w cmd internal pkg
