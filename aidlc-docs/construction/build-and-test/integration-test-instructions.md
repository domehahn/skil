# Integration Test Instructions

Run the cross-package suite:

```bash
GOWORK=off GOCACHE=/tmp/skil-go-cache go test -race ./...
```

Run compatibility and external-scanner checks:

```bash
go test ./compat/asps ./compat/external-scanner
python3 -m unittest discover -s compat/external-scanner -p 'test_*.py'
```

Run documentation and schema gates:

```bash
make check-docs
go test ./schemas
```
