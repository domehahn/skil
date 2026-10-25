# Continuous Assurance

`skil continuous check` provides an explicit, one-shot assurance control loop:

```bash
skil continuous check ./my-skill \
  --policy .skil/policy.yaml \
  --state .skil/assurance-state.json \
  --format json
```

Each run scans the skill, evaluates the configured policy, compares the current artifact and assurance-closure digests with the previous state, and atomically persists a versioned state file.

Digest drift sets `runtime_pin_valid` to `false` and `attestation_refresh_required` to `true`. A first run also has no valid runtime pin because no prior reviewed state exists. The command is intentionally one-shot and opt-in; it does not start a background process or silently perform network operations beyond the explicitly selected scan configuration.
