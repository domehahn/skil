# ADR 0001: Separate contract, analysis, evaluation, and policy

Status: accepted. `pkg/skil` owns contracts; independent internal packages own
loading, scanning, verification, evaluation, evidence, policy, and reporting.
This prevents scan success from implying runtime enforcement or policy approval.
