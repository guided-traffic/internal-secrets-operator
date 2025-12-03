# Kubernetes Secret Operator

## Project Overview

This project implements a custom Kubernetes controller that automatically generates random secret values. It can be used for auto-generating random credentials for applications running on Kubernetes.

**Repository:** https://github.com/guided-traffic/k8s-secret-operator

**Note:** This project is in early development and has no releases yet. All changes are considered breaking changes, but since there are no users yet, backwards compatibility is not required at this stage.

## Architecture

### Core Components

1. **Secret Controller** - Watches Kubernetes Secrets with specific annotations
2. **Value Generator** - Generates cryptographically secure random values (using `crypto/rand`)
3. **Reconciliation Logic** - Handles the update of secrets with generated values

### Annotation Schema

The operator uses annotations with the prefix `secgen.gtrfc.com/`:

| Annotation | Description | Values |
|------------|-------------|--------|
| `autogenerate` | Comma-separated list of field names to auto-generate | e.g., `password`, `password,api-key` |
| `type` | Default type of generated value for all fields | `string` (default), `bytes` |
| `length` | Default length for all fields | Integer (default: 32) |
| `type.<field>` | Type for a specific field (overrides default) | `string`, `bytes` |
| `length.<field>` | Length for a specific field (overrides default) | Integer |
| `string.uppercase` | Include uppercase letters (A-Z) | `true` (default), `false` |
| `string.lowercase` | Include lowercase letters (a-z) | `true` (default), `false` |
| `string.numbers` | Include numbers (0-9) | `true` (default), `false` |
| `string.specialChars` | Include special characters | `true`, `false` (default) |
| `string.allowedSpecialChars` | Which special characters to use | e.g., `!@#$%^&*` |
| `generated-at` | Timestamp of last patch by operator (set by operator) | ISO 8601 format |

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
    secgen.gtrfc.com/autogenerate: password,encryption-key
    secgen.gtrfc.com/type: string
    secgen.gtrfc.com/length: "24"
    secgen.gtrfc.com/string.specialChars: "true"
    secgen.gtrfc.com/string.allowedSpecialChars: "!@#$"
    secgen.gtrfc.com/type.encryption-key: bytes
    secgen.gtrfc.com/length.encryption-key: "32"
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
    secgen.gtrfc.com/autogenerate: password,encryption-key
    secgen.gtrfc.com/type: string
    secgen.gtrfc.com/length: "24"
    secgen.gtrfc.com/string.specialChars: "true"
    secgen.gtrfc.com/string.allowedSpecialChars: "!@#$"
    secgen.gtrfc.com/type.encryption-key: bytes
    secgen.gtrfc.com/length.encryption-key: "32"
    secgen.gtrfc.com/generated-at: "2025-12-03T10:00:00+01:00"
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
k8s-secret-operator/
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
│       └── k8s-secret-operator/
├── test/
│   └── e2e/
├── Containerfile
├── Makefile
├── go.mod
└── README.md
```

## TODO

### Code Changes Required

- [x] Update annotation prefix from `secret-generator.v1.guided-traffic.com/` to `secgen.gtrfc.com/`
- [x] Remove `regenerate` annotation support
- [x] Remove `uuid` and `hex` generation types
- [x] Rename `base64` type to `bytes`
- [x] Remove `secure` annotation (operator is always secure by design)
- [x] Implement field-specific type/length configuration (`type.<field>`, `length.<field>`)
- [x] Simplify operator-set annotations to only `generated-at`
- [x] Implement configuration file loading at startup
- [x] Add configurable charset for `string` type (uppercase, lowercase, numbers, specialChars, allowedSpecialChars)
- [x] Add validation: at least one charset option must be enabled
- [x] Implement Warning Events on Secrets when errors occur

### Helm Chart

- [ ] Add `config` section to `values.yaml` with all configuration options
- [ ] Create ConfigMap template for operator configuration
- [ ] Mount ConfigMap as config file in deployment
- [ ] Add `rbac.clusterRoleBinding.enabled` option (default: true)
- [ ] Document how to set up RoleBindings for restricted namespace access

### Testing

- [x] Update unit tests for new annotation schema
- [ ] Update integration tests
- [ ] Update e2e tests
- [x] Add tests for configuration file loading
- [ ] Add tests for charset configuration

### Documentation

- [ ] Update README.md with new annotation schema
- [ ] Update sample secrets in `config/samples/`
- [ ] Update Helm chart values documentation
- [ ] Document configuration file options
