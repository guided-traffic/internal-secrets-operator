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
| `type` | Default type of generated value for all fields | `string` (default), `bytes`, `rsa`, `ecdsa`, `ed25519` |
| `length` | Default length for all fields | Integer (default: 32) |
| `type.<field>` | Type for a specific field (overrides default) | `string`, `bytes`, `rsa`, `ecdsa`, `ed25519` |
| `length.<field>` | Length for a specific field (overrides default) | Integer |
| `curve` | Default elliptic curve for `ecdsa` fields | `P-256` (default), `P-384`, `P-521` |
| `curve.<field>` | Elliptic curve for a specific field (overrides default) | `P-256`, `P-384`, `P-521` |
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
| `rsa` | RSA keypair (PKCS#1 PEM) | Key size in bits (`2048`, `4096`) | TLS certificates, signing, encryption |
| `ecdsa` | ECDSA keypair (PKCS#1 PEM) | *(ignored, use `curve` annotation)* | TLS certificates, JWT signing (ES256/ES384/ES512) |
| `ed25519` | Ed25519 keypair (PKCS#1 PEM) | *(ignored, fixed 256-bit)* | SSH keys, modern signing |

**Note:** Kubernetes stores all secret data Base64-encoded. The `bytes` type generates raw bytes which are then Base64-encoded by Kubernetes when stored.

**Note:** For keypair types (`rsa`, `ecdsa`, `ed25519`), the operator generates two Secret data entries per field: `<field>` (Private Key PEM) and `<field>.pub` (Public Key PEM). All keys use PKCS#1 PEM format.

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
  verbs: ["get", "list", "watch", "update", "patch", "create", "delete"]
# Events permissions for recording events
# Core API ("") is used by leader election
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create", "patch"]
# events.k8s.io is used by controller-runtime Eventf
- apiGroups: ["events.k8s.io"]
  resources: ["events"]
  verbs: ["create", "patch"]
```

**Notes:**
- `create` and `delete` verbs for secrets are required for secret replication features.
- Two Events API groups are required: Core API (`""`) for leader election events, and `events.k8s.io` for controller-runtime `Eventf()` calls (requires Kubernetes 1.19+).

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
  maintenanceWindows:
    enabled: false
    windows: []
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
| `rotation.maintenanceWindows.enabled` | Enable maintenance windows for rotation | `false` |
| `rotation.maintenanceWindows.windows` | List of maintenance window definitions | `[]` |
| `rotation.maintenanceWindows.windows[].name` | Descriptive name for the window | - |
| `rotation.maintenanceWindows.windows[].days` | List of weekdays (e.g., `["saturday", "sunday"]`) | - |
| `rotation.maintenanceWindows.windows[].startTime` | Start time in 24h format (HH:MM) | - |
| `rotation.maintenanceWindows.windows[].endTime` | End time in 24h format (HH:MM) | - |
| `rotation.maintenanceWindows.windows[].timezone` | IANA timezone (e.g., `Europe/Berlin`) | - |

**Note:** At least one of `uppercase`, `lowercase`, `numbers`, or `specialChars` must be `true`.

**Note:** When `maintenanceWindows.enabled` is `true`, `endTime` must be after `startTime`, otherwise the operator will fail to start.

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
    maintenanceWindows:
      enabled: false
      windows: []
      # Example:
      # - name: "weekend-night"
      #   days: ["saturday", "sunday"]
      #   startTime: "03:00"
      #   endTime: "05:00"
      #   timezone: "Europe/Berlin"
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

### Git Workflow

**Important:** Copilot never commits to Git autonomously. All Git commits are performed exclusively by the developer.

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

## Secret Replication Feature (DRAFT - IN PLANNING)

### Overview

The operator will support replicating Secrets across namespaces in two modes:
- **Pull-based replication**: A Secret can pull data from Secrets in other namespaces
- **Push-based replication**: A Secret can push its data to other namespaces

### Feature Toggles

Both the existing Secret Generator and the new Secret Replicator can be independently enabled/disabled via configuration:

| Config Option | Description | Default |
|---------------|-------------|---------|
| `secret-generator` | Enable/disable automatic secret value generation | `true` |
| `secret-replicator` | Enable/disable secret replication across namespaces | `true` |

**Configuration location:** `/etc/secret-operator/config.yaml` and Helm values

### Annotations for Replication

All replication annotations use the `iso.gtrfc.com/` prefix:

| Annotation | Description | Values |
|------------|-------------|--------|
| `replicatable-from-namespaces` | Allowlist of namespaces that are allowed to replicate FROM this Secret (source side) | Comma-separated list with patterns: `"namespace1,namespace[0-9]*"` or `"*"` for all |
| `replicate-from` | Source Secret to replicate data from (target side) | Format: `"namespace/secret-name"` |
| `replicate-to` | Push this secret to specified namespaces (push-based) | Comma-separated list: `"namespace1,namespace2"` |

### Mutual Consent Security Model

For **pull-based replication**, both sides must explicitly consent:

1. **Source Secret** (where data comes from) must have `replicatable-from-namespaces` annotation allowing the target namespace
2. **Target Secret** (where data will be copied to) must have `replicate-from` annotation pointing to the source

**Example:**

```yaml
# Source Secret in namespace "production"
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
  namespace: production
  annotations:
    iso.gtrfc.com/replicatable-from-namespaces: "staging"
data:
  username: cHJvZHVzZXI=
  password: cHJvZHBhc3M=
---
# Target Secret in namespace "staging"
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
  namespace: staging
  annotations:
    iso.gtrfc.com/replicate-from: "production/db-credentials"
data: {}
```

Result: Data from `production/db-credentials` is copied to `staging/db-credentials`

**Security:** This prevents unauthorized access - a Secret cannot be replicated unless it explicitly allows replication to specific namespaces.

### Pull-based Replication

Pull-based replication requires **mutual consent** from both source and target Secrets.

**Source Secret** (provides data):
- Has `replicatable-from-namespaces` annotation specifying allowed target namespaces
- Supports glob patterns for flexible namespace matching

**Target Secret** (receives data):
- Has `replicate-from` annotation pointing to the source (`"namespace/secret-name"`)
- Explicitly requests replication from that specific source

**Pattern matching for `replicatable-from-namespaces` (Glob syntax):**
- Exact namespace names: `"namespace1"`
- Multiple namespaces: `"namespace1,namespace2"`
- Glob patterns: `"namespace-*"`, `"prod-?"`, `"ns-[0-9]"`
- All namespaces: `"*"`

**Supported glob syntax:**
- `*` - matches any sequence of characters
- `?` - matches any single character
- `[abc]` - matches any character in the set (a, b, or c)
- `[a-z]` - matches any character in the range (a through z)
- `[0-9]` - matches any digit

**Behavior:**
- Replication only occurs when BOTH annotations match
- Data from source Secret is copied to target Secret
- Existing data in target is overwritten (replicated data wins)
- Target Secrets automatically sync when source changes
- If source is deleted, target keeps last known data (snapshot)
- Each target can only replicate from one source Secret

### Push-based Replication

A Secret with the `replicate-to` annotation will push its data to specified namespaces.

**Behavior:**
- Creates a copy of the Secret in each target namespace (comma-separated list supported)
- If target exists and has `replicated-from` annotation: Update
- If target exists without annotation: Skip and create Warning Event on source
- Pushed Secrets automatically sync when source changes
- Cross-namespace ownership via Finalizers + `replicated-from` annotation
- When source is deleted, all pushed Secrets are automatically cleaned up
