# Build Instructions

## Local build

```bash
GOWORK=off GOCACHE=/tmp/skil-go-cache go build -buildvcs=false -trimpath -o bin/skil ./cmd/skil
```

## Release-oriented checks

```bash
go mod verify
gofmt -l cmd internal pkg tests
GOWORK=off GOCACHE=/tmp/skil-go-cache go vet ./...
```

The release workflow additionally builds Linux amd64, macOS arm64, and Windows amd64 artifacts, generates SPDX SBOMs, and verifies release attestations.
