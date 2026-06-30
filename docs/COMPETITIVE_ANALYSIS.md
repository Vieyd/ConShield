# Competitive Analysis

## Scope and assumptions

This document positions ConShield against common container-security tools and categories at a high level. It avoids vendor pricing, market share, version-specific behavior, and claims that require current vendor verification.

The comparison is intentionally conservative: ConShield is a local-first prototype and demo-ready control plane. It complements specialized tools; it does not claim to replace them.

## Comparison matrix

| Capability | ConShield | Trivy | Falco | Kyverno | Wazuh | Commercial CNAPP category |
|---|---|---|---|---|---|---|
| Image scan input | Yes | Yes | No | No | Partial | Yes |
| Policy-as-code gate | Yes | Partial | No | Yes | Partial | Yes |
| CI/CD exit code gate | Yes | Yes | No | Partial | Partial | Yes |
| Protected local run | Yes | No | No | No | No | Category-dependent |
| Docker lifecycle collector | Yes | No | Partial | No | Partial | Category-dependent |
| Runtime/Falco event ingestion | Yes | No | Yes | No | Partial | Yes |
| Sensor trust registry | Yes | No | No | No | Partial | Yes |
| Sensor trust enforcement | Yes | No | No | No | Partial | Yes |
| Signed sensor event verification | Yes | No | No | No | Partial | Category-dependent |
| SIEM correlation rules | Yes | No | Partial | No | Yes | Yes |
| Incident creation | Yes | No | No | No | Yes | Yes |
| Evidence export | Yes | Partial | Partial | Partial | Yes | Yes |
| Unified CLI | Yes | Yes | Yes | Yes | Partial | Category-dependent |
| Web GUI | Yes | No | Partial | No | Yes | Yes |
| Local/offline demo pack | Yes | Partial | Partial | Partial | Partial | Category-dependent |
| Kubernetes admission control | Planned | No | No | Yes | No | Yes |
| Enterprise multi-cluster management | Out of scope | No | No | Partial | Partial | Yes |
| Compliance/certification | Out of scope | No | No | No | Category-dependent | Category-dependent |

Legend: `Yes` means the capability is directly represented in the current ConShield workflow or the named category. `Partial` means the capability can be approximated, integrated, or covered in a narrower way. `Category-dependent` means products in that broad category vary. `Planned` means intentionally future work. `Out of scope` means not a goal for the current local prototype.

## Scanner-only comparison

Trivy is scanner-focused: it is strong at producing vulnerability and configuration findings. ConShield can consume Trivy-compatible fixture output and map it into security events, policy decisions, alerts, incidents, and evidence.

ConShield is not differentiated by replacing a scanner engine. It is differentiated by showing what happens after a scan result enters a broader operator workflow.

## Runtime detection comparison

Falco is runtime detection-focused: it observes runtime behavior and raises events. ConShield can replay Falco-compatible events and connect them to runtime source health, sensor trust, signature status, SIEM alerts, incidents, and evidence.

ConShield does not replace a kernel-level runtime sensor. It demonstrates how runtime signals can be normalized, correlated, and explained in a local control plane.

## Kubernetes policy comparison

Kyverno is Kubernetes policy/admission-focused. ConShield currently has a local policy-as-code gate for protected container run and CI/CD image gate workflows, but it does not provide Kubernetes admission control in this version.

That choice keeps the base demo small and reproducible. Kubernetes admission integration belongs on the roadmap, not in the current scope.

## SIEM/XDR comparison

Wazuh represents a broader SIEM/XDR monitoring category. ConShield includes SIEM-style correlation, alerts, incidents, and evidence, but only for a focused container-security workflow.

ConShield is intentionally narrower. It is useful for education, prototype validation, and explainable local demos rather than full enterprise monitoring coverage.

## Commercial CNAPP comparison

Commercial CNAPP platforms are broad enterprise platform categories that often combine cloud posture, workload protection, image scanning, runtime security, Kubernetes coverage, compliance workflows, and enterprise integrations.

ConShield should not be positioned as a replacement for that category. It is a transparent local-first workflow that demonstrates how scanning, policy, runtime, lifecycle, sensor trust, SIEM, incidents, and evidence can connect.

## Where ConShield is intentionally smaller

- No enterprise multi-tenant management.
- No production Kubernetes admission controller yet.
- No full mTLS or production key-management layer yet.
- No broad compliance certification workflow.
- No claim of complete vulnerability coverage.
- No dependency on live cloud accounts or external telemetry for the default demo.

## Where ConShield is differentiated

ConShield is not differentiated by outperforming specialized tools in their strongest area. It is differentiated by integrating several container-security stages into a local, reproducible, evidence-first workflow suitable for education, small-team DevSecOps, and prototype deployments.

The key difference is the chain:

```text
scan -> policy gate -> runtime/lifecycle -> sensor trust/signatures -> SIEM -> incidents -> evidence
```

## Risks of over-positioning

The safest positioning is specific and humble. Avoid claims that ConShield is a complete enterprise platform, a formal compliance-attestation product, a universal replacement for commercial CNAPP, or a guarantee of protection. The project is strongest when presented as an integrated, inspectable prototype with deterministic validation.

## Recommended defense wording

Use:

> ConShield is a local-first DevSecOps/SIEM control plane for container security. It connects scanner input, policy decisions, runtime and lifecycle signals, sensor trust, signed event checks, SIEM correlation, incidents, and evidence into one reproducible workflow.

Avoid:

> ConShield replaces enterprise CNAPP tools.

Better:

> ConShield demonstrates a smaller, transparent workflow that can complement scanners, runtime sensors, policy engines, and SIEM platforms in educational or prototype contexts.
