# Security Architecture

Security design of the internal-secrets-operator. User documentation:
[README.md](README.md); contributor documentation: [DEVELOPER.md](DEVELOPER.md).

## Roles and trust boundaries

| Role | Controls | Trust implication |
|------|----------|-------------------|
| Cluster operator / installer | Helm values, operator config (`/etc/secret-operator/config.yaml`), RBAC mode | Can define `globalPullBasedPermissions` that bypass source-side consent; can widen/narrow the operator's namespace reach |
| Namespace tenant (can write Secrets/ConfigMaps in a namespace) | Annotations on their objects | Can request generation; can offer their objects for replication; can pull anything whose source (or a global permission) allowlists their namespace |
| Operator ServiceAccount | Runtime API access | Holds the union of all granted RBAC — cluster-wide read/write on Secrets and ConfigMaps in the default install |
| Kubernetes API / etcd | Storage of all secret material | Out of the operator's control — etcd encryption at rest and API-server RBAC are prerequisites, not features of this operator |

```
        ┌─────────────────────────────────────────────────────────────┐
        │ Cluster                                                     │
        │                                                             │
        │  ┌───────────────┐   ClusterRole(Binding) / RoleBindings    │
        │  │ operator pod  │──────────────────────────────┐           │
        │  │ (SA, nonroot, │                              ▼           │
        │  │ distroless)   │   watch/update    ┌────────────────────┐ │
        │  └──────┬────────┘◄─────────────────►│  Kubernetes API    │ │
        │         │ reads at startup           │  (Secrets, CMs,    │ │
        │  ┌──────▼────────┐                   │  Events, Leases)   │ │
        │  │ ConfigMap:    │                   └─────────┬──────────┘ │
        │  │ operator      │                             ▼            │
        │  │ config        │                   ┌────────────────────┐ │
        │  └───────────────┘                   │ etcd (at-rest      │ │
        │    ▲ written by installer            │ encryption =       │ │
        │    │ (trust anchor for global        │ cluster concern)   │ │
        │    │  pull permissions)              └────────────────────┘ │
        └─────────────────────────────────────────────────────────────┘
          namespace tenants interact only via annotations on their
          own Secrets/ConfigMaps — never with the operator directly
```

## Data and secret flow

- Secret values are generated **in-process** from `crypto/rand`
  ([generator.go](pkg/generator/generator.go)) and written to the Kubernetes
  API in a single `Update`. They exist in operator memory only during a
  reconcile.
- The operator makes **no network connections** except to the Kubernetes API.
  Nothing is sent to external services; keys are not derived from external
  entropy.
- Replication copies data API → operator memory → API. Replicated targets are
  full plaintext copies: replication **widens the exposure surface** of a
  secret to every allowlisted/target namespace and everything that can read
  Secrets there.
- Secret values are never logged and never placed in Events (event messages
  contain error descriptions, truncated to 100 characters).
- The operator config (not secret material) is mounted read-only from a
  ConfigMap; the container runs with a read-only root filesystem.

## Isolation and tenancy model

**Mechanism: mutual consent for pull replication.** Data crosses a namespace
boundary only when the source allowlists the target namespace
(`replicatable-from-namespaces`, glob-capable) *and* the target explicitly
names the source (`replicate-from`). Push replication is consent-by-source
(the source decides where its data goes); unmanaged same-name objects in
target namespaces are never overwritten or adopted (ownership = exact
`replicated-from` match).

**What this defends against:**

- A tenant pulling another namespace's Secret without the source having opted
  in — denied, Warning Event on the target.
- Push replication silently clobbering an existing, foreign object in the
  target namespace.
- Typo'd source references leaking data from unexpected objects (exact
  `namespace/name` matching only).

**What this does NOT defend against:**

- **Namespace-level RBAC is the real access boundary.** Consent grants access
  to a *namespace*, not to a workload or user. Anyone who can create an
  annotated Secret in an allowlisted namespace receives the data. If untrusted
  parties can write Secrets in a namespace, do not allowlist it.
- **`replicatable-from-namespaces: "*"`** publishes the object to every
  namespace in the cluster (including future ones).
- **Global pull permissions bypass source consent** by design (for sources the
  installer cannot annotate). They shift the decision to whoever controls the
  operator config. Mitigations: exact namespace matching (DNS-1123-validated,
  patterns rejected at startup), mandatory glob on the source object name,
  explicit per-kind opt-in (`allowSecret`/`allowConfigMap` default `false`).
- **Anyone with `update` permission on a source object** can add
  `replicate-to`/`replicatable-from-namespaces` and export it — replication
  consent is annotation-based, so write access to the object equals consent
  authority. There is no admission control layer.
- The operator does not protect Secrets from principals with direct RBAC read
  access — it is not an encryption or access-control layer.

## Privilege footprint

Default Helm install ([rbac.yaml](deploy/helm/internal-secrets-operator/templates/rbac.yaml)),
bound cluster-wide via ClusterRoleBinding:

| Permission | Needed for | Consequence if compromised |
|------------|-----------|----------------------------|
| `secrets` get/list/watch cluster-wide | watches, replication sources | Full read of **all** cluster Secrets |
| `secrets` update/patch/create/delete | generation, push replication, cleanup | Full write on all Secrets, incl. deletion |
| `configmaps` full verbs | ConfigMap replication | Same for ConfigMaps |
| `events` (core + `events.k8s.io`) create/patch | user feedback, leader election | Event spam at worst |
| `leases` (coordination.k8s.io) | leader election | DoS of the operator's own HA at worst |

The operator pod itself runs hardened: distroless static image, non-root UID
65532, no privilege escalation, all capabilities dropped, read-only rootfs,
seccomp `RuntimeDefault`, resource-limited.

**Reducing the footprint — restricted mode:** disable the ClusterRoleBinding
(`rbac.clusterRoleBinding.enabled: false`) and create per-namespace
RoleBindings referencing the ClusterRole. The operator can then only touch
namespaces with a binding. Caveats:

- Leader election needs a RoleBinding in the operator's **own** namespace
  (lease permissions are part of the same ClusterRole).
- Replication requires bindings in **both** source and target namespaces.
- The compromise scenario shrinks from "all namespaces" to "bound namespaces".

The kustomize deployment ([config/rbac/](config/rbac/)) is a dev/test variant:
cluster-wide binding, no lease permissions, leader election disabled.

## Validation story

| Input | Validation | Failure mode |
|-------|-----------|--------------|
| Operator config file | Full validation at startup: types, lengths, charset classes, maintenance windows (time format, order, timezone), global permissions (DNS-1123 namespaces, non-empty valid glob, kind opt-in) | **Fail-closed**: operator refuses to start (CrashLoop with reason in log) |
| `type`/`param`/`curve` annotations | Checked at generation time against known values | Warning Event, Secret untouched (whole reconcile aborted — no partial writes) |
| Charset annotations | At least one class enabled, special chars non-empty when enabled | Warning Event, Secret untouched |
| `length` for RSA | ≥ 1024 enforced by the generator | Warning Event, Secret untouched |
| `rotate` durations | Below `rotation.minInterval` → rejected per field | Warning Event, field not rotated. **Gap:** syntactically malformed durations are silently ignored (fall back to next level / no rotation) — no event |
| `replicate-from` reference | Exact `namespace/name` parse | Warning Event, no requeue (user must fix) |
| Replication consent | Annotation allowlist (glob) first, then global permissions (exact ns + name glob) | Warning Event with the deny reason |

## Rotation and change propagation

- Rotation intentionally **overwrites** values; `rotation.minInterval`
  (default `5m`) bounds rotation frequency to protect the API server from
  accidental tight loops.
- Rotation state is a single `generated-at` annotation per Secret: any field
  write resets the rotation clock of **all** fields in that Secret. Per-field
  rotation timing is therefore approximate — relevant if you rotate
  compliance-critical credentials on strict schedules; use separate Secrets
  for strict independence.
- Maintenance windows only defer rotation, never initial generation.
- Replicated targets sync on source change via watches (no polling interval to
  tune). Deleted sources leave **snapshots** in pull targets — revocation of a
  replicated credential requires cleaning up targets explicitly.
- Replication updates **merge** keys: a key removed from the source persists
  in all targets. Rotating a credential by *renaming* the key leaves the old
  value live in every target — rotate in place instead, or recreate targets.
- Consumers do not learn about rotation automatically — pair with
  [Reloader](https://github.com/stakater/Reloader) or equivalent, and prefer
  short-lived pods over long-cached credentials.

## Residual risks / hardening checklist

Actionable, honest list — items marked ☐ are open, with suggested mitigations:

- ☐ **Modulo bias in string generation.**
  [generator.go](pkg/generator/generator.go) maps random bytes with
  `charset[randomByte % len(charset)]`. For charset sizes that don't divide
  256 (e.g. 62), leading charset characters are up to 25 % more likely than
  others. The entropy loss for ≥ 32-char values is small, but generated
  strings are **not uniformly distributed**. Fix: rejection sampling or
  `crypto/rand.Int`. Until then, compensate with longer values.
- ☐ **Push cleanup can delete pull targets.** Cleanup matches only the
  `replicated-from` annotation, which pull targets share. A source that is
  both pulled from and pushed deletes its pull targets on source deletion.
  Avoid mixing both modes on one source; a fix needs a push-specific marker.
- ☐ **Stale keys in replication targets** (merge semantics, see above) —
  removed/renamed source keys are never removed from targets.
- ☐ **Metrics endpoint is unauthenticated plain HTTP** (`:8080`). Exposes
  operational metrics only, but restrict with a NetworkPolicy; none is
  shipped with the chart.
- ☐ **No NetworkPolicy in the chart.** The operator needs egress to the API
  server only — a deny-all-plus-API policy is a cheap win.
- ☐ **Unfiltered replicator watch lists cluster-wide on every object event.**
  Not a confidentiality issue (cache-backed), but a resource-exhaustion
  vector in very large/busy clusters.
- ☐ **Malformed `rotate` values fail silently** — a typo (`"24hr"`) disables
  rotation without any signal. Check `kubectl describe` for the absence of
  rotation events after changes.
- ☑ **Config fail-closed at startup**; no silent misconfiguration.
- ☑ **No partial Secret writes** on generation errors.
- ☑ **Hardened pod defaults** (distroless, nonroot 65532, read-only rootfs,
  no capabilities, seccomp).
- ☑ **Supply chain:** CI runs gosec, govulncheck (plus a daily scheduled
  vulnerability watch), Trivy image scans, ClamAV, SBOM + provenance on
  released images; dependencies are Renovate-managed.

Cluster-level prerequisites this operator assumes but cannot provide:
etcd encryption at rest, restrictive RBAC on Secret read access, audit
logging of Secret access.

## Reporting vulnerabilities

Report suspected vulnerabilities privately via
[GitHub Security Advisories](https://github.com/guided-traffic/internal-secrets-operator/security/advisories)
("Report a vulnerability"). Please do not open public issues for exploitable
findings. There is currently no separate `SECURITY.md` policy file; this
section is the authoritative process description.
