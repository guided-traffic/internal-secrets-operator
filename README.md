# Internal Secrets Operator

[![Build Status](https://github.com/guided-traffic/internal-secrets-operator/actions/workflows/release.yml/badge.svg)](https://github.com/guided-traffic/internal-secrets-operator/actions)
[![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/guided-traffic/internal-secrets-operator/main/.github/badges/coverage.json)](https://github.com/guided-traffic/internal-secrets-operator)
[![Go Report Card](https://goreportcard.com/badge/github.com/guided-traffic/internal-secrets-operator)](https://goreportcard.com/report/github.com/guided-traffic/internal-secrets-operator)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A Kubernetes operator that automatically generates random secret values. Use it for auto-generating random credentials for applications running on Kubernetes.

## Features

- 🔐 **Automatic Secret Generation** - Automatically generates cryptographically secure random values for Kubernetes Secrets
- 🔄 **Automatic Secret Rotation** - Periodically rotate secrets based on configurable time intervals
- 🎯 **Annotation-Based** - Simple annotation-based configuration, no CRDs required
- 📏 **Configurable Length** - Customize the length of generated secrets per field
- 🔢 **Multiple Types** - Support for `string` and `bytes` generation
- 🔤 **Customizable Charset** - Configure which characters to include in generated strings
- ✅ **Idempotent** - Only generates values for empty fields, preserves existing data

## Quick Start

### Installation

#### Using Helm

```bash
helm repo add internal-secrets-operator https://guided-traffic.github.io/internal-secrets-operator
helm install internal-secrets-operator internal-secrets-operator/internal-secrets-operator
```

#### Using Kustomize

```bash
kubectl apply -k https://github.com/guided-traffic/internal-secrets-operator/config/default
```

### Usage

Create a Secret with the `autogenerate` annotation:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: example-secret
  annotations:
    iso.gtrfc.com/autogenerate: password
data:
  username: c29tZXVzZXI=  # someuser (base64 encoded)
```

After the operator reconciles, the Secret will be updated:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: example-secret
  annotations:
    iso.gtrfc.com/autogenerate: password
    iso.gtrfc.com/generated-at: "2025-12-03T10:00:00+01:00"
type: Opaque
data:
  username: c29tZXVzZXI=
  password: TWVwSU83L2huNXBralNTMHFwU3VKSkkwNmN4NmRpNTBBcVpuVDlLOQ==
```

## Annotations

All annotations use the prefix `iso.gtrfc.com/`.

### Core Annotations

| Annotation | Description | Default |
|------------|-------------|---------|
| `autogenerate` | Comma-separated list of field names to auto-generate | *required* |
| `type` | Default type for all fields: `string` or `bytes` | `string` |
| `length` | Default length for all fields | `32` |
| `type.<field>` | Type for a specific field (overrides `type`) | - |
| `length.<field>` | Length for a specific field (overrides `length`) | - |
| `rotate` | Default rotation interval for all fields | - |
| `rotate.<field>` | Rotation interval for a specific field (overrides `rotate`) | - |
| `generated-at` | Timestamp when values were generated (set by operator) | - |

### Generation Types

| Type | Description | `length` meaning | Use-Case |
|------|-------------|------------------|----------|
| `string` | Alphanumeric string | Number of characters | Passwords, API keys, tokens |
| `bytes` | Raw random bytes | Number of bytes | Encryption keys, binary secrets |

> **Note:** Kubernetes stores all secret data Base64-encoded. The `bytes` type generates raw bytes which are then Base64-encoded by Kubernetes when stored.

## Examples

### Generate Multiple Fields

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: multi-field-secret
  annotations:
    iso.gtrfc.com/autogenerate: password,api-key,token
type: Opaque
```

### Custom Length

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: custom-length-secret
  annotations:
    iso.gtrfc.com/autogenerate: password
    iso.gtrfc.com/length: "64"
type: Opaque
```

### Generate Raw Bytes (e.g., for Encryption Keys)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: encryption-secret
  annotations:
    iso.gtrfc.com/autogenerate: encryption-key
    iso.gtrfc.com/type: bytes
    iso.gtrfc.com/length: "32"
type: Opaque
```

### Different Types per Field

Generate a password (string) and an encryption key (bytes) with different lengths:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mixed-secret
  annotations:
    iso.gtrfc.com/autogenerate: password,encryption-key
    iso.gtrfc.com/type: string
    iso.gtrfc.com/length: "24"
    iso.gtrfc.com/type.encryption-key: bytes
    iso.gtrfc.com/length.encryption-key: "32"
type: Opaque
data:
  username: c29tZXVzZXI=
```

Result:
- `password`: 24-character alphanumeric string
- `encryption-key`: 32 random bytes (Base64-encoded)
- `username`: preserved as-is

## Automatic Secret Rotation

The operator can automatically rotate (regenerate) secrets at regular intervals. This is useful for:

- **Security compliance** - Regular credential rotation as required by security policies
- **Reducing blast radius** - Limiting the time window a compromised credential can be used
- **Automated credential management** - No manual intervention needed for rotation

### How Rotation Works

1. When a Secret is created, the operator generates values and records the timestamp in `generated-at`
2. The operator calculates when the next rotation is due based on the `rotate` annotation
3. When the rotation interval expires, all fields with rotation enabled are regenerated
4. The `generated-at` timestamp is updated to the current time
5. The cycle repeats automatically

> **Important:** Rotation **overwrites existing values**. This is different from initial generation, which only fills empty fields.

### Duration Format

The `rotate` annotation accepts durations in Go format:

| Unit | Suffix | Example |
|------|--------|---------|
| Seconds | `s` | `30s` |
| Minutes | `m` | `15m` |
| Hours | `h` | `24h` |
| Days | `d` | `7d` |

You can combine units: `1h30m` (1 hour and 30 minutes), `7d12h` (7 days and 12 hours)

### Basic Rotation Example

Rotate password every 24 hours:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: rotating-secret
  annotations:
    iso.gtrfc.com/autogenerate: password
    iso.gtrfc.com/rotate: "24h"
type: Opaque
```

### Per-Field Rotation Intervals

Different fields can have different rotation schedules:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: multi-rotation-secret
  annotations:
    iso.gtrfc.com/autogenerate: password,api-key,encryption-key
    iso.gtrfc.com/rotate: "24h"              # Default: rotate daily
    iso.gtrfc.com/rotate.password: "7d"      # Override: rotate weekly
    iso.gtrfc.com/rotate.api-key: "30d"      # Override: rotate monthly
    # encryption-key uses default (24h)
type: Opaque
```

Result:
- `password`: Rotates every 7 days
- `api-key`: Rotates every 30 days
- `encryption-key`: Rotates every 24 hours (default)

### Selective Rotation

Only rotate specific fields, while others remain static:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: selective-rotation-secret
  annotations:
    iso.gtrfc.com/autogenerate: password,api-key
    iso.gtrfc.com/rotate.password: "7d"
    # api-key has no rotate annotation → never auto-rotated
type: Opaque
```

Result:
- `password`: Rotates every 7 days
- `api-key`: Generated once, never automatically rotated

### Rotation Events

When `rotation.createEvents` is enabled in the configuration, the operator creates Kubernetes Events when secrets are rotated:

```bash
kubectl describe secret rotating-secret
```

```
Events:
  Type    Reason          Age   From                        Message
  ----    ------          ----  ----                        -------
  Normal  SecretRotated   5s    internal-secrets-operator   Rotated 1 field(s): password
```

### Minimum Rotation Interval

To prevent accidental tight rotation loops (which could cause excessive API load), the operator enforces a minimum rotation interval. By default, this is **5 minutes**.

If you specify a rotation interval below `minInterval`, the operator:
1. Creates a **Warning Event** on the Secret
2. Uses `minInterval` as the actual rotation interval

```yaml
# This will trigger a warning and use minInterval (5m) instead
annotations:
  iso.gtrfc.com/rotate: "30s"  # Too short!
```

### Rotation Configuration

Configure rotation behavior via Helm values:

```yaml
config:
  rotation:
    # Minimum allowed rotation interval (prevents tight loops)
    minInterval: 5m

    # Create Normal Events when secrets are rotated
    # Useful for auditing, but may create many events with frequent rotations
    createEvents: false
```

Or via command line:

```bash
helm install internal-secrets-operator internal-secrets-operator/internal-secrets-operator \
  --set config.rotation.minInterval=10m \
  --set config.rotation.createEvents=true
```

### Application Considerations

When using automatic rotation, ensure your applications can handle credential changes:

1. **Reload on change** - Use tools like [Reloader](https://github.com/stakater/Reloader) to restart pods when secrets change
2. **Watch for changes** - Applications can watch the Secret and reload credentials dynamically
3. **Graceful handling** - Implement retry logic for authentication failures during rotation windows
4. **Coordinate rotation** - Consider rotation timing to minimize disruption (e.g., during low-traffic periods)

#### Example: Using Reloader

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  annotations:
    reloader.stakater.com/auto: "true"  # Restart when any mounted secret changes
spec:
  template:
    spec:
      containers:
        - name: app
          envFrom:
            - secretRef:
                name: rotating-secret
```

## Regenerating Secrets

The operator respects existing values and will **not** overwrite them. To regenerate a secret value, you have two options:

### Option 1: Delete and Recreate the Secret

```bash
kubectl delete secret my-secret
kubectl apply -f my-secret.yaml
```

### Option 2: Delete Specific Keys from the Secret

To regenerate only specific fields, delete those keys from the Secret's data:

```bash
# Using kubectl patch to remove a specific key
kubectl patch secret my-secret --type=json -p='[{"op": "remove", "path": "/data/password"}]'
```

Or edit the Secret directly:

```bash
kubectl edit secret my-secret
# Remove the key you want to regenerate from the data section
```

The operator will automatically detect the missing field and generate a new value for it.

## Helm Chart Configuration

The operator's default behavior can be customized via Helm values:

```yaml
config:
  defaults:
    # Default generation type: "string" or "bytes"
    type: string
    # Default length for generated values
    length: 32
    # String generation options (only used when type is "string")
    string:
      # Include uppercase letters (A-Z)
      uppercase: true
      # Include lowercase letters (a-z)
      lowercase: true
      # Include numbers (0-9)
      numbers: true
      # Include special characters
      specialChars: false
      # Which special characters to use (when specialChars is true)
      allowedSpecialChars: "!@#$%^&*()_+-=[]{}|;:,.<>?"

  rotation:
    # Minimum allowed rotation interval (prevents accidental tight loops)
    minInterval: 5m
    # Create Normal Events when secrets are rotated
    createEvents: false
```

### Example: Enable Special Characters by Default

```bash
helm install internal-secrets-operator internal-secrets-operator/internal-secrets-operator \
  --set config.defaults.string.specialChars=true \
  --set config.defaults.string.allowedSpecialChars='!@#$%'
```

> **Note:** At least one of `uppercase`, `lowercase`, `numbers`, or `specialChars` must be enabled.

For the complete list of all Helm chart values including image configuration, resources, autoscaling, monitoring, and more, see the [Helm Chart Documentation](deploy/helm/internal-secrets-operator/README.md).

## Configuration File

The operator reads its configuration from a YAML file at startup. This allows customizing default behavior without code changes.

### File Location

| Deployment Method | Configuration Path |
|-------------------|-------------------|
| Helm Chart | `/etc/secret-operator/config.yaml` (via ConfigMap) |
| Manual Deployment | `/etc/secret-operator/config.yaml` (default) |

When deployed via Helm, the configuration is managed through the `config` section in `values.yaml` and automatically mounted as a ConfigMap.

### Configuration Options

```yaml
defaults:
  # Generation type: "string" or "bytes"
  # - string: Generates alphanumeric characters (configurable charset)
  # - bytes: Generates raw random bytes
  type: string

  # Length of generated values
  # - For "string": number of characters
  # - For "bytes": number of bytes
  length: 32

  # String generation options (only used when type is "string")
  string:
    # Include uppercase letters (A-Z)
    uppercase: true

    # Include lowercase letters (a-z)
    lowercase: true

    # Include numbers (0-9)
    numbers: true

    # Include special characters
    specialChars: false

    # Which special characters to use (when specialChars is true)
    allowedSpecialChars: "!@#$%^&*()_+-=[]{}|;:,.<>?"

rotation:
  # Minimum allowed rotation interval
  # Prevents accidental tight rotation loops that could overload the API server
  minInterval: 5m

  # Create Normal Events when secrets are rotated
  # Useful for auditing, but may create many events with frequent rotations
  createEvents: false
```

### Configuration Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `defaults.type` | string | `string` | Default generation type. Valid values: `string`, `bytes` |
| `defaults.length` | integer | `32` | Default length for generated values (must be > 0) |
| `defaults.string.uppercase` | boolean | `true` | Include uppercase letters (A-Z) in generated strings |
| `defaults.string.lowercase` | boolean | `true` | Include lowercase letters (a-z) in generated strings |
| `defaults.string.numbers` | boolean | `true` | Include numbers (0-9) in generated strings |
| `defaults.string.specialChars` | boolean | `false` | Include special characters in generated strings |
| `defaults.string.allowedSpecialChars` | string | `!@#$%^&*()_+-=[]{}|;:,.<>?` | Which special characters to use when `specialChars` is enabled |
| `rotation.minInterval` | duration | `5m` | Minimum allowed rotation interval. Rotation intervals below this value trigger a warning and use `minInterval` instead |
| `rotation.createEvents` | boolean | `false` | Create Normal Events when secrets are rotated. Useful for auditing |

### Validation Rules

The operator validates the configuration at startup and will fail to start if:

1. **Invalid type**: `defaults.type` must be either `string` or `bytes`
2. **Invalid length**: `defaults.length` must be a positive integer
3. **No charset enabled**: At least one of `uppercase`, `lowercase`, `numbers`, or `specialChars` must be `true`
4. **Empty special chars**: If `specialChars` is `true`, `allowedSpecialChars` must not be empty

### Configuration Priority

Configuration values are applied in the following order (highest priority first):

1. **Per-field annotations** (`iso.gtrfc.com/type.<field>`, `iso.gtrfc.com/length.<field>`)
2. **Secret-level annotations** (`iso.gtrfc.com/type`, `iso.gtrfc.com/length`)
3. **Configuration file** (`/etc/secret-operator/config.yaml`)
4. **Built-in defaults** (used if config file doesn't exist)

### Example Configurations

#### Passwords with Special Characters

```yaml
defaults:
  type: string
  length: 24
  string:
    uppercase: true
    lowercase: true
    numbers: true
    specialChars: true
    allowedSpecialChars: "!@#$%&*"
```

#### Numbers Only (e.g., PINs)

```yaml
defaults:
  type: string
  length: 6
  string:
    uppercase: false
    lowercase: false
    numbers: true
    specialChars: false
```

#### Encryption Keys (Raw Bytes)

```yaml
defaults:
  type: bytes
  length: 32
```

#### Weekly Rotation with Events

```yaml
defaults:
  type: string
  length: 32
  string:
    uppercase: true
    lowercase: true
    numbers: true
    specialChars: true
    allowedSpecialChars: "!@#$%&*"

rotation:
  minInterval: 1h       # Allow rotations as frequent as hourly
  createEvents: true    # Log rotation events for auditing
```

### Manual Deployment

If you're deploying the operator without Helm, create the configuration file manually:

```bash
# Create the config directory
sudo mkdir -p /etc/secret-operator

# Create the config file
sudo cat > /etc/secret-operator/config.yaml << 'EOF'
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
EOF
```

The operator will use built-in defaults if the configuration file doesn't exist.

## Error Handling

When an error occurs (e.g., invalid annotation values), the operator:

1. Does **not** modify the Secret
2. Creates a **Warning Event** on the Secret with details about the error
3. Logs the error for debugging

You can view errors with:

```bash
kubectl describe secret <name>
```

## RBAC and Namespace Access

By default, the operator is deployed with a **ClusterRoleBinding**, giving it access to Secrets in **all namespaces**. This is convenient for most use cases but may not meet your security requirements.

### Restricting to Specific Namespaces

For environments where you need fine-grained control over which namespaces the operator can access, you can disable the ClusterRoleBinding and create RoleBindings manually in specific namespaces.

#### Step 1: Disable ClusterRoleBinding

Install or upgrade the Helm chart with the ClusterRoleBinding disabled:

```bash
helm install internal-secrets-operator internal-secrets-operator/internal-secrets-operator \
  --set rbac.clusterRoleBinding.enabled=false
```

Or in your `values.yaml`:

```yaml
rbac:
  clusterRoleBinding:
    enabled: false
```

#### Step 2: Create RoleBindings in Target Namespaces

Create a RoleBinding in each namespace where the operator should have access. The RoleBinding references the ClusterRole (which is still created) but only grants access within that specific namespace.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: internal-secrets-operator
  namespace: my-app-namespace  # The namespace to grant access to
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: internal-secrets-operator  # Must match the ClusterRole name from the Helm release
subjects:
  - kind: ServiceAccount
    name: internal-secrets-operator  # Must match the ServiceAccount name from the Helm release
    namespace: internal-secrets-operator  # The namespace where the operator is deployed
```

> **Note:** If you customized the Helm release name or used `fullnameOverride`, adjust the ClusterRole and ServiceAccount names accordingly.

#### Example: Granting Access to Multiple Namespaces

To grant access to `production`, `staging`, and `development` namespaces:

```bash
# Create RoleBindings in each namespace
for ns in production staging development; do
  kubectl create rolebinding internal-secrets-operator \
    --clusterrole=internal-secrets-operator \
    --serviceaccount=internal-secrets-operator:internal-secrets-operator \
    --namespace=$ns
done
```

Or using a manifest:

```yaml
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: internal-secrets-operator
  namespace: production
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: internal-secrets-operator
subjects:
  - kind: ServiceAccount
    name: internal-secrets-operator
    namespace: internal-secrets-operator
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: internal-secrets-operator
  namespace: staging
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: internal-secrets-operator
subjects:
  - kind: ServiceAccount
    name: internal-secrets-operator
    namespace: internal-secrets-operator
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: internal-secrets-operator
  namespace: development
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: internal-secrets-operator
subjects:
  - kind: ServiceAccount
    name: internal-secrets-operator
    namespace: internal-secrets-operator
```

### Why Use a ClusterRole with RoleBindings?

You might wonder why we reference a **ClusterRole** in the RoleBinding instead of creating namespace-scoped Roles. This is a common Kubernetes pattern:

- **ClusterRole** defines the permissions (what actions can be performed on which resources)
- **RoleBinding** grants those permissions within a specific namespace

This approach allows you to:
1. Define the permissions once (in the ClusterRole)
2. Selectively grant those permissions per namespace (via RoleBindings)
3. Easily add/remove namespace access without modifying the operator deployment

## Security

- Uses `crypto/rand` for cryptographically secure random number generation
- Never logs secret values
- Follows least-privilege RBAC principles
- Only modifies Secrets with the specific annotation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by [kubernetes-secret-generator](https://github.com/mittwald/kubernetes-secret-generator) by Mittwald
- Built with [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime)