# Performance Test Instructions

The repository does not currently define a mandatory performance threshold. For repeatable comparative measurements, use the benchmark harness:

```bash
python3 benchmark/runner/run_benchmark.py --help
```

Measure before and after changes to analyzer count, cache behavior, provider retries, and collection worker count. Record artifact corpus, tool versions, flags, wall time, memory, findings, and coverage so results remain comparable.
