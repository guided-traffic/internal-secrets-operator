# Developer Guide

Contributor documentation for the internal-secrets-operator. User-facing docs
live in [README.md](README.md), the security design in
[SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md).

## Repository layout

```
internal-secrets-operator/
├── cmd/
│   └── main.go                  # Entrypoint: flags, config load, manager + controller wiring
├── internal/controller/         # The three reconcilers (not importable from outside)
│   ├── secret_controller.go             # Generator: annotations → random values/keypairs, rotation
│   ├── secret_replicator_controller.go  # Secret pull/push replication + finalizer cleanup
│   └── configmap_replicator_controller.go # Same for ConfigMaps (no generator conflict check)
├── pkg/                         # Reusable, controller-independent logic
│   ├── config/                  # Config file schema, defaults, validation, maintenance windows
│   ├── generator/               # crypto/rand value + keypair generation
│   └── replicator/              # Annotation constants, consent checks, replication helpers
├── config/                      # Kustomize deployment (dev/test only; no config file, no leases)
│   ├── default/                 # Namespace secret-operator-system + rbac + manager
│   ├── manager/                 # Deployment, image ghcr.io/guided-traffic/internal-secrets-operator
│   ├── rbac/                    # ClusterRole/Binding/ServiceAccount (no coordination.k8s.io)
│   └── samples/                 # Example Secrets/ConfigMaps (not part of any kustomization)
├── deploy/helm/internal-secrets-operator/  # Production Helm chart
├── test/
│   ├── integration/             # envtest-based tests (build tag: integration)
│   └── e2e/                     # Kind + Helm E2E tests (build tag: e2e)
├── .github/workflows/           # CI/CD — see "CI pipeline" (note: file names are swapped!)
├── Containerfile                # Two-stage build → distroless nonroot
├── Makefile                     # All build/test/lint/deploy targets
└── .releaserc.json              # semantic-release config (Conventional Commits)
```

## Package responsibilities

### `cmd/`

| File | Responsibility |
|------|----------------|
| [main.go](cmd/main.go) | Flag parsing (`-metrics-bind-address` :8080, `-health-probe-bind-address` :8081, `-leader-elect` false, `-config` `/etc/secret-operator/config.yaml`), config load (exit 1 on invalid), scheme (core types only — no CRDs), manager with leader-election ID `secret-operator.guided-traffic.com`, feature-toggled controller registration, `/healthz` + `/readyz` |

Feature toggles gate at **registration time**: a disabled feature means the
controller is never constructed and no watch exists — there are no
per-reconcile feature checks.

### `pkg/config/`

| File | Responsibility |
|------|----------------|
| [config.go](pkg/config/config.go) | Config schema + YAML loading, built-in defaults, `Validate()` (fail startup on any error), `Duration` with `d`-suffix support, charset building. **`defaults.type` accepts only `string`, `bytes`, `rsa`, `ecdsa`, `ed25519`** — PQ types are annotation-only. |
| [maintenance_window.go](pkg/config/maintenance_window.go) | Window validation (days, `HH:MM`, `endTime > startTime`, IANA timezone), `IsInAnyWindow`, `NextWindowStart` for requeue scheduling |

### `pkg/generator/`

| File | Responsibility |
|------|----------------|
| [generator.go](pkg/generator/generator.go) | `Generator` interface + `SecretGenerator` impl. Strings/bytes via `crypto/rand`; RSA (PKCS#1, ≥1024 bits), ECDSA (SEC 1 + PKIX, P-256/384/521), Ed25519 (PKCS#8 + PKIX); ML-KEM via stdlib `crypto/mlkem` (768/1024), ML-DSA (65/87) and SLH-DSA (SHA2, 6 param sets) via `cloudflare/circl` |

### `pkg/replicator/`

| File | Responsibility |
|------|----------------|
| [replicator.go](pkg/replicator/replicator.go) | All replication annotation constants + the finalizer, `ValidateReplication` (glob allowlist vs target namespace), `ReplicateSecret` (merge copy + status annotations), source-ref parsing, finalizer helpers, ownership check (`replicated-from` string equality), generate+pull conflict detection |
| [configmap.go](pkg/replicator/configmap.go) | ConfigMap variants of copy/create (incl. `binaryData`) |
| [global_permissions.go](pkg/replicator/global_permissions.go) | `ValidatePullConsent` (annotation first, then global permissions), `IsGloballyAllowed` (exact namespaces + name glob), watch-predicate helper `MatchesAnyGlobalSource` |

### `internal/controller/`

| File | Responsibility |
|------|----------------|
| [secret_controller.go](internal/controller/secret_controller.go) | Generator reconciler: annotation parsing/priority resolution, per-field generation, rotation scheduling, maintenance-window deferral, events. Injectable `Clock` for tests. |
| [secret_replicator_controller.go](internal/controller/secret_replicator_controller.go) | Secret pull/push reconciler, deletion/cleanup handling, watch mappers, user-friendly error translation (truncated at 100 chars) |
| [configmap_replicator_controller.go](internal/controller/configmap_replicator_controller.go) | Structurally identical to the Secret replicator minus the `ConflictingFeatures` check; reuses its event reason constants |

## Core flows

### Generator reconcile ([secret_controller.go](internal/controller/secret_controller.go))

Watch: `For(&corev1.Secret{})` with a predicate on **presence** of the
`autogenerate` annotation (an empty value still triggers, then no-ops).

1. Get Secret; parse `autogenerate` (comma-split, trim, drop empties) — zero
   fields → done.
2. Read `generated-at` (RFC 3339; unparseable → treated as absent).
3. Per field, in annotation order: resolve type/length/curve/param via
   priority `<key>.<field>` → `<key>` → config → built-in default, then:
   - interval < `minInterval` → Warning `RotationFailed`; existing field is
     left alone, empty field is still generated,
   - rotation due but outside maintenance window → Normal `RotationDeferred`
     (only when a next window start is computable), requeue at window start,
   - field exists and no rotation due → skip,
   - otherwise generate; keypair types also fill `<field>.pub`.
4. **Any generation error aborts the whole reconcile** — no partial writes,
   Warning `GenerationFailed`, no requeue (user must fix the annotations).
5. If anything changed: set `generated-at = now`, single `Update`, emit
   `GenerationSucceeded` / `RotationSucceeded` (the latter only when
   `rotation.createEvents`).
6. Requeue at the earliest next rotation across fields.

**Why one `generated-at` per Secret:** rotation state lives in a single
annotation, so any field write resets the clock for all fields of that Secret.
Simple, but it means per-field rotation timing is approximate — documented as
such in the README. Changing this would require per-field timestamps
(annotation per field) and a migration.

### Pull replication ([secret_replicator_controller.go](internal/controller/secret_replicator_controller.go))

1. Deletion? → cleanup handler (below), nothing else.
2. `autogenerate` + `replicate-from` both set → Warning `ConflictingFeatures`,
   stop. (Secret controller has no such check — generation still runs; the
   conflict only disables replication.)
3. `replicate-from` set → parse `"ns/name"` (invalid → Warning, no requeue —
   user must fix), get source (missing → Warning), source being deleted →
   Warning `SourceDeleted` + keep snapshot, consent check
   (`ValidatePullConsent`: annotation allowlist first, then global
   permissions), then merge-copy + `Update` + Normal `ReplicationSucceeded`.
4. Else `replicate-to` set → push (below). Pull wins when both are set.

### Push replication + cleanup

1. Ensure finalizer `iso.gtrfc.com/replicate-to-cleanup` on the **source**.
2. For each target namespace: get same-name object.
   - Missing → create copy (data, labels, `replicated-from`,
     `last-replicated-at`; **no** source annotations, no ownerReference —
     cross-namespace ownerRefs are invalid in Kubernetes, hence the finalizer
     design).
   - Exists with matching `replicated-from` → merge-update.
   - Exists without it → Warning `PushFailed`, skip (never adopt).
   - Per-target errors are logged/evented but don't abort the loop.
3. On source deletion: list **all** Secrets/ConfigMaps cluster-wide, delete
   every one whose `replicated-from` equals `"<ns>/<name>"`, then remove the
   finalizer. Delete errors keep the finalizer and retry with backoff.

Known sharp edge: pull targets carry the same `replicated-from` annotation,
so a source that is both pulled from and pushed will take its pull targets
down with it on deletion. See
[SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md#residual-risks--hardening-checklist).

### Watch topology (both replicators)

Three watches per replicator:

1. Primary: objects with non-empty `replicate-from` **or** `replicate-to`.
2. Source watch: objects with `replicatable-from-namespaces` or matching a
   global permission → mapper enqueues all targets whose `replicate-from`
   points at the changed object (auto-sync).
3. **Unfiltered** watch: any object event → mapper lists all objects and
   enqueues push sources that target the changed object's namespace with the
   same name. This is what retries a blocked push once the blocking object
   disappears. Cost: every Secret/ConfigMap event triggers a cluster-wide
   `List` from the cache — fine at moderate scale, a candidate for indexing
   if clusters grow large.

## Extension checklists

### Add a new generation type

1. [pkg/config/config.go](pkg/config/config.go): add `Type<X>` constant (+
   default param constant if parameterized). Extend `Config.Validate()` only
   if the type should be allowed as config-file default.
2. [pkg/generator/generator.go](pkg/generator/generator.go): add
   `Generate<X>Keypair(...)` to the `Generator` interface and implementation
   (use `crypto/rand`); reject it in `GenerateWithCharset` like the other
   keypair types.
3. [internal/controller/secret_controller.go](internal/controller/secret_controller.go):
   add a case in `generateValue` (resolve params via `getFieldParam`).
4. Tests: table-driven generator tests + integration test in
   [test/integration/](test/integration/), E2E coverage in
   [test/e2e/e2e_test.go](test/e2e/e2e_test.go).
5. Docs: README generation-types table + naming conventions,
   [CLAUDE.md](CLAUDE.md) annotation schema.

### Add a new annotation

1. Constant in [secret_controller.go](internal/controller/secret_controller.go)
   (generation) or [pkg/replicator/replicator.go](pkg/replicator/replicator.go)
   (replication) — never inline strings.
2. Resolution helper following the `getField*` priority pattern
   (`<key>.<field>` → `<key>` → config default).
3. Wire into `generateFieldValue`/reconcile; emit a Warning Event on invalid
   values (do not fail silently — see the `rotate` parsing gap below).
4. Integration test + README annotations table.

### Add a config option

1. Struct field + YAML tag in [pkg/config/config.go](pkg/config/config.go),
   default in `NewDefaultConfig()`, zero-value handling in `LoadConfig`,
   checks in `Validate()` (fail-closed).
2. Expose in Helm: [values.yaml](deploy/helm/internal-secrets-operator/values.yaml)
   under `config:` — the ConfigMap template renders the whole block 1:1, no
   template changes needed.
3. Unit test in [pkg/config/config_test.go](pkg/config/config_test.go);
   README configuration reference.

## Build / test / lint

| Task | Command | Notes |
|------|---------|-------|
| Build | `make build` | `fmt` + `vet` + compile to `bin/manager` |
| Run locally | `make run` | uses current kubeconfig, `--zap-log-level=debug` |
| Unit tests | `make test-unit` | `-short`, no envtest binaries needed for pkg tests |
| All tests + coverage | `make test` | downloads envtest assets (K8s 1.36.x) into `./bin` |
| Integration tests | `make test-integration` | envtest (real API server + etcd, no cluster), build tag `integration`, timeout 60m |
| E2E | `make e2e-local` | Kind cluster `secret-operator-test` + Helm install + `make test-e2e` + teardown |
| Lint | `make lint` | golangci-lint v2 (11 linters, see [.golangci.yml](.golangci.yml)) + `go vet` |
| Complexity | `make cyclo` | gocyclo, threshold 15, tests excluded |
| Security scan | `make gosec` | gosec v2.22.0 |
| Vulnerabilities | `make vuln` | govulncheck |
| Coverage badge | `make coverage-json` | writes `.github/badges/coverage.json` |
| Container image | `make docker-build` | `IMG` defaults to `ghcr.io/guided-traffic/internal-secrets-operator:latest` (dev only — releases go to Docker Hub, see below) |

Test conventions: table-driven tests; envtest for controller behavior
(per-test managers with metrics disabled, unique controller names, `GenerateName`
namespaces); injectable `Clock` (`MockClock` in
[suite_test.go](test/integration/suite_test.go)) for rotation/window tests;
target ≥ 80 % coverage (informational — CI has no failing gate, coverage only
feeds the badge and a PR comment).

## CI pipeline

⚠️ **The two workflow file names are swapped relative to their content:**

| File | Actual content |
|------|----------------|
| [.github/workflows/release.yml](.github/workflows/release.yml) | `Test and Release` — the CI pipeline (PRs + main) |
| [.github/workflows/build.yml](.github/workflows/build.yml) | `Release Docker & Helm` — publishing, runs on GitHub Release |

**On every PR and push to main** (`release.yml`, self-hosted runners):
ClamAV malware scan, unit tests, gosec, govulncheck, golangci-lint, gocyclo
(≤ 15), integration tests (envtest), E2E (Kind v1.33.4 + Helm install +
`make test-e2e`), Trivy container scan (CRITICAL/HIGH gate), combined
coverage report (sticky PR comment with delta vs main).

**On push to main additionally:** the coverage badge JSON is built and
`semantic-release` runs — analyzing Conventional Commits, tagging
`v<semver>`, creating the GitHub Release, and committing
`.github/badges/coverage.json` with `[skip ci]` (via `BOT_PAT` so follow-up
workflows trigger).

**On the published GitHub Release** (`build.yml`): multi-tag image build
(`<version>`, `<major>.<minor>`, `<major>`, `sha`, `latest`; linux/amd64) →
pushed to **Docker Hub** `guidedtraffic/internal-secrets-operator` with
provenance + SBOM; Docker Scout CVE scan; Helm chart packaged with version =
tag and published to the `gh-pages` Helm repo
(`https://guided-traffic.github.io/internal-secrets-operator`) and as release
assets. The `version:`/`appVersion:` in the committed
[Chart.yaml](deploy/helm/internal-secrets-operator/Chart.yaml) are
placeholders (`0.1.0`) — real versions are injected at package time only.

**Daily** ([vuln-watch.yml](.github/workflows/vuln-watch.yml), 04:00 UTC):
`make vuln` against main; on failure it opens/updates a deduplicated GitHub
issue — because a newly published CVE turns main red without any commit and
would otherwise silently block every open PR.

## Release process

1. Merge PRs with Conventional Commit messages (`fix:` → patch, `feat:` →
   minor, `feat!:`/`BREAKING CHANGE:` → major).
2. Everything else is automatic: semantic-release on main → GitHub Release →
   image + chart publishing. No manual version bumps, no CHANGELOG file
   (release notes live on the GitHub Releases page).

## Conventions

- Conventional Commits (enforced by semantic-release's commit-analyzer).
- `context.Context` first parameter for all operations; wrapped errors
  (`fmt.Errorf("...: %w", err)`); structured logging via
  `sigs.k8s.io/controller-runtime/pkg/log` — never log secret values.
- All annotation keys as constants — no inline `iso.gtrfc.com/...` strings.
- `crypto/rand` only; `math/rand` is forbidden for secret material.
- Linters: `errcheck`, `govet`, `ineffassign`, `staticcheck`, `unused`,
  `misspell`, `unconvert`, `unparam`, `goconst`, `prealloc`, `revive`
  (+ `gofmt`/`goimports` with local prefix
  `github.com/guided-traffic/internal-secrets-operator`).
- RBAC kubebuilder markers exist only on the generator controller and are
  **not** the source of truth — the Helm chart RBAC is maintained by hand.
  Keep [rbac.yaml](deploy/helm/internal-secrets-operator/templates/rbac.yaml)
  and [config/rbac/role.yaml](config/rbac/role.yaml) in sync manually when
  permissions change.
