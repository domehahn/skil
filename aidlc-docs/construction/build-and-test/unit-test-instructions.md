# Unit Test Instructions

Run all unit and package tests with:

```bash
GOWORK=off GOCACHE=/tmp/skil-go-cache go test -race ./...
```

Focused checks for the implemented improvements:

```bash
go test ./internal/continuous ./internal/provider/resilience ./internal/provider/osv ./internal/provider/openssf ./pkg/engine ./schemas
go test ./internal/cli -run 'TestContinuous|TestExplain'
```

Tests requiring local TCP listeners need a network-capable test environment.
