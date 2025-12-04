# Internal Secrets Operator

## Project Overview

This project implements a custom Kubernetes controller that automatically generates random secret values. It can be used for auto-generating random credentials for applications running on Kubernetes.

**Repository:** https://github.com/guided-traffic/internal-secrets-operator

**Note:** This project is in early development and has no releases yet. All changes are considered breaking changes, but since there are no users yet, backwards compatibility is not required at this stage.

## Architecture

### Core Components

1. **Secret Controller** - Watches Kubernetes Secrets with specific annotations
2. **Value Generator** - Generates cryptographically secure random values (using `crypto/rand`)
3. **Reconciliation Logic** - Handles the update of secrets with generated values

### Annotation Schema

The operator uses annotations with the prefix `iso.gtrfc.com/`:

| Annotation | Description | Values |
|------------|-------------|--------|
| `autogenerate` | Comma-separated list of field names to auto-generate | e.g., `password`, `password,api-key` |
| `type` | Default type of generated value for all fields | `string` (default), `bytes` |
| `length` | Default length for all fields | Integer (default: 32) |
| `type.<field>` | Type for a specific field (overrides default) | `string`, `bytes` |
| `length.<field>` | Length for a specific field (overrides default) | Integer |
| `rotate` | Default rotation interval for all fields | Duration (e.g., `24h`, `7d`) |
| `rotate.<field>` | Rotation interval for a specific field (overrides default) | Duration |
| `string.uppercase` | Include uppercase letters (A-Z) | `true` (default), `false` |
| `string.lowercase` | Include lowercase letters (a-z) | `true` (default), `false` |
| `string.numbers` | Include numbers (0-9) | `true` (default), `false` |
| `string.specialChars` | Include special characters | `true`, `false` (default) |
| `string.allowedSpecialChars` | Which special characters to use | e.g., `!@#$%^&*` |
| `generated-at` | Timestamp of last generation/rotation (set by operator) | ISO 8601 format |

**Priority:** Annotation values override config file defaults.

### Generation Types

| Type | Description | `length` meaning | Use-Case |
|------|-------------|------------------|----------|
| `string` | Alphanumeric string | Number of characters | Passwords, readable tokens |
| `bytes` | Raw random bytes | Number of bytes | Encryption keys, binary secrets |

**Note:** Kubernetes stores all secret data Base64-encoded. The `bytes` type generates raw bytes which are then Base64-encoded by Kubernetes when stored.

### Behavior

- **Existing values are respected**: If a field already has a value, the operator does NOT overwrite it
- **User changes are preserved**: If a user manually changes a value, the operator does nothing
- **Regeneration**: To regenerate a value, delete the field from `data` or delete and recreate the Secret
- **New secrets**: When a Secret is created, all fields listed in `autogenerate` that don't have values are generated

### Error Handling

When an error occurs (e.g., invalid charset configuration), the operator:
1. Does NOT modify the Secret
2. Creates a **Warning Event** on the Secret with details about the error
3. Logs the error for debugging

Users can see errors with `kubectl describe secret <name>`.

### Namespace Access

The operator requires RBAC permissions to access Secrets. By default, the Helm chart creates a **ClusterRoleBinding** giving the operator access to all namespaces.

**For restricted namespace access:**
1. Disable the ClusterRoleBinding in Helm values: `rbac.clusterRoleBinding.enabled: false`
2. Manually create RoleBindings in the specific namespaces where the operator should work

This approach keeps RBAC explicit and transparent – the operator only has access to namespaces where RoleBindings exist.

### Example

**Input:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: example-secret
  annotations:
    iso.gtrfc.com/autogenerate: password,encryption-key
    iso.gtrfc.com/type: string
    iso.gtrfc.com/length: "24"
    iso.gtrfc.com/string.specialChars: "true"
    iso.gtrfc.com/string.allowedSpecialChars: "!@#$"
    iso.gtrfc.com/type.encryption-key: bytes
    iso.gtrfc.com/length.encryption-key: "32"
data:
  username: c29tZXVzZXI=
```

**Output (after operator reconciliation):**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: example-secret
  annotations:
    iso.gtrfc.com/autogenerate: password,encryption-key
    iso.gtrfc.com/type: string
    iso.gtrfc.com/length: "24"
    iso.gtrfc.com/string.specialChars: "true"
    iso.gtrfc.com/string.allowedSpecialChars: "!@#$"
    iso.gtrfc.com/type.encryption-key: bytes
    iso.gtrfc.com/length.encryption-key: "32"
    iso.gtrfc.com/generated-at: "2025-12-03T10:00:00+01:00"
type: Opaque
data:
  username: c29tZXVzZXI=
  password: <base64-encoded-24-char-string-with-special-chars>
  encryption-key: <base64-encoded-32-random-bytes>
```

## Technical Specifications

### RBAC Requirements

The controller needs the following permissions:

```yaml
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch", "update", "patch"]
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create", "patch"]
```

### Defaults

| Setting | Default Value |
|---------|---------------|
| Type | `string` |
| Length | `32` |

### Configuration File

The operator reads its configuration from a YAML file at startup. This allows customizing default behavior without code changes.

**Default config file path:** `/etc/secret-operator/config.yaml`

**Example configuration:**

```yaml
defaults:
  type: string
  length: 32
  string:
    uppercase: true
    lowercase: true
    numbers: true
    specialChars: false
    allowedSpecialChars: "!@#$%^&*()_+-=[]{}|;:,.<>?"

rotation:
  minInterval: 5m
  createEvents: false
```

**Configuration options:**

| Option | Description | Default |
|--------|-------------|---------|
| `defaults.type` | Default generation type | `string` |
| `defaults.length` | Default length | `32` |
| `defaults.string.uppercase` | Include uppercase letters (A-Z) | `true` |
| `defaults.string.lowercase` | Include lowercase letters (a-z) | `true` |
| `defaults.string.numbers` | Include numbers (0-9) | `true` |
| `defaults.string.specialChars` | Include special characters | `false` |
| `defaults.string.allowedSpecialChars` | Which special characters to use | `!@#$%^&*()_+-=[]{}|;:,.<>?` |
| `rotation.minInterval` | Minimum allowed rotation interval | `5m` |
| `rotation.createEvents` | Create Normal Events when secrets are rotated | `false` |

**Note:** At least one of `uppercase`, `lowercase`, `numbers`, or `specialChars` must be `true`.

### Helm Chart Configuration

The configuration is exposed via Helm values:

```yaml
# values.yaml
config:
  defaults:
    type: string
    length: 32
    string:
      uppercase: true
      lowercase: true
      numbers: true
      specialChars: false
      allowedSpecialChars: "!@#$%^&*()_+-=[]{}|;:,.<>?"
  rotation:
    minInterval: 5m
    createEvents: false
```

## Coding Guidelines

### Go Best Practices

1. Use `context.Context` for all operations
2. Proper error handling with wrapped errors
3. Structured logging with `sigs.k8s.io/controller-runtime/pkg/log`
4. Use constants for annotation keys

### Security Considerations

1. Use `crypto/rand` for random number generation (never `math/rand`)
2. Avoid logging secret values
3. Implement proper RBAC with least privilege

### Testing Requirements

1. Minimum 80% code coverage
2. Table-driven tests
3. Mock external dependencies
4. Use envtest for controller tests

## File Structure

```
internal-secrets-operator/
├── .github/
│   ├── copilot-instructions.md
│   └── workflows/
├── cmd/
│   └── main.go
├── internal/
│   └── controller/
│       ├── secret_controller.go
│       └── secret_controller_test.go
├── pkg/
│   └── generator/
│       ├── generator.go
│       └── generator_test.go
├── config/
│   ├── default/
│   ├── manager/
│   ├── rbac/
│   └── samples/
├── deploy/
│   └── helm/
│       └── internal-secrets-operator/
├── test/
│   └── e2e/
├── Containerfile
├── Makefile
├── go.mod
└── README.md
```

## TODO

### Per-Secret Charset Annotations

- [ ] Implement per-Secret charset annotations (`string.uppercase`, `string.lowercase`, `string.numbers`, `string.specialChars`, `string.allowedSpecialChars`) in `secret_controller.go`
- [ ] Add e2e tests for per-Secret charset annotations

### Periodic Secret Rotation

Implement automatic secret regeneration based on a configurable time interval. This allows secrets to be rotated periodically without manual intervention.

#### Annotation Schema

| Annotation | Description | Example |
|------------|-------------|---------|
| `iso.gtrfc.com/rotate` | Default rotation interval for all fields | `24h`, `7d`, `1h30m` |
| `iso.gtrfc.com/rotate.<field>` | Rotation interval for a specific field (overrides default) | `rotate.password: "7d"` |

**Duration Format:** Go duration format (e.g., `5m`, `1h`, `24h`, `7d` where `d` = 24h)

#### Behavior

1. **Rotation Trigger:** When `time.Now() - generated-at >= rotate duration`, all fields listed in `autogenerate` are regenerated (existing values are overwritten)
2. **Timestamp Update:** After rotation, `generated-at` is updated to the current time
3. **Per-Field Rotation:** If `rotate.<field>` is set, only that field uses the specified interval. Fields without a specific rotation interval use the default `rotate` value
4. **Fields without rotation:** If no `rotate` annotation exists (neither global nor per-field), the field is never automatically rotated (current behavior)
5. **RequeueAfter:** After reconciliation, the controller returns `RequeueAfter` with the remaining time until the next rotation. This ensures the Secret is automatically re-reconciled at the right time without polling

#### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `rotation.minInterval` | Minimum allowed rotation interval (prevents accidental tight loops) | `5m` |
| `rotation.createEvents` | Create Normal Events when secrets are rotated | `false` |

**Note for `rotation.createEvents`:** Enabling this can be useful for auditing, but be aware that frequent rotations will create many Events. This can increase load on the Kubernetes API server and make the Secret object harder to read in `kubectl describe` due to the long event list.

#### Example

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: rotating-secret
  annotations:
    iso.gtrfc.com/autogenerate: password,api-key,encryption-key
    iso.gtrfc.com/rotate: "24h"
    iso.gtrfc.com/rotate.password: "7d"
    iso.gtrfc.com/rotate.api-key: "30d"
    # encryption-key uses default 24h rotation
type: Opaque
```

#### Implementation Tasks

- [x] Add `rotation` section to config struct in `pkg/config/config.go`
  - `minInterval` (default: `5m`)
  - `createEvents` (default: `false`)
- [x] Parse `rotate` and `rotate.<field>` annotations in `secret_controller.go`
- [x] Validate rotation duration against `minInterval` (create Warning Event if too short)
- [x] Implement rotation logic: compare `generated-at` with current time and rotation interval
- [x] Force-regenerate fields when rotation is due (override "existing values are respected" behavior)
- [x] Update `generated-at` timestamp after rotation
- [x] Implement `RequeueAfter` calculation (minimum of all field rotation times)
- [x] Create Normal Event on rotation (if `rotation.createEvents` is enabled)
- [x] Add unit tests for rotation logic
- [x] Add integration tests for rotation with mocked time
- [x] Add e2e tests for rotation feature
- [x] Update Helm chart `values.yaml` with `rotation` config section
- [x] Update README.md with rotation documentation
- [x] Update sample secrets in `config/samples/` with rotation examples
