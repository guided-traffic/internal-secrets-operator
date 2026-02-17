# Internal Secrets Operator

[![Build Status](https://github.com/guided-traffic/internal-secrets-operator/actions/workflows/release.yml/badge.svg)](https://github.com/guided-traffic/internal-secrets-operator/actions)
[![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/guided-traffic/internal-secrets-operator/main/.github/badges/coverage.json)](https://github.com/guided-traffic/internal-secrets-operator)
[![Go Report Card](https://goreportcard.com/badge/github.com/guided-traffic/internal-secrets-operator)](https://goreportcard.com/report/github.com/guided-traffic/internal-secrets-operator)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A Kubernetes operator that automatically generates random secret values. Use it for auto-generating random credentials for applications running on Kubernetes.

## Features

### Secret Generation
- 🔐 **Automatic Secret Generation** - Automatically generates cryptographically secure random values for Kubernetes Secrets
- 🔄 **Automatic Secret Rotation** - Periodically rotate secrets based on configurable time intervals
- 🎯 **Annotation-Based** - Simple annotation-based configuration, no CRDs required
- 📏 **Configurable Length** - Customize the length of generated secrets per field
- 🔢 **Multiple Types** - Support for `string` and `bytes` generation
- 🔤 **Customizable Charset** - Configure which characters to include in generated strings
- ✅ **Idempotent** - Only generates values for empty fields, preserves existing data

### Secret Replication
- 🔄 **Pull-based Replication** - Secrets can pull data from other namespaces with mutual consent
- 📤 **Push-based Replication** - Automatically push secrets to multiple target namespaces
- 🛡️ **Secure by Design** - Mutual consent model prevents unauthorized access
- 🎯 **Pattern Matching** - Support for glob patterns in namespace allowlists (`*`, `?`, `[abc]`, `[a-z]`)
- 🔁 **Auto-sync** - Target Secrets automatically update when source changes
- 🧹 **Auto-cleanup** - Pushed Secrets are automatically deleted when source is removed
- 🚫 **Conflict Detection** - Prevents conflicting features (`autogenerate` + `replicate-from`)
- ✨ **Flexible Combinations** - Generate secrets in one namespace and share with others

## Requirements

- Kubernetes 1.25+

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
| `curve` | Default elliptic curve for `ecdsa` fields | `P-256` |
| `curve.<field>` | Elliptic curve for a specific field (overrides `curve`) | - |
| `rotate` | Default rotation interval for all fields | - |
| `rotate.<field>` | Rotation interval for a specific field (overrides `rotate`) | - |
| `generated-at` | Timestamp when values were generated (set by operator) | - |

### Generation Types

| Type | Description | `length` meaning | Use-Case |
|------|-------------|------------------|----------|
| `string` | Alphanumeric string | Number of characters | Passwords, API keys, tokens |
| `bytes` | Raw random bytes | Number of bytes | Encryption keys, binary secrets |
| `rsa` | RSA keypair (PKCS#1 PEM) | Key size in bits (`2048`, `4096`) | TLS certificates, signing, encryption |
| `ecdsa` | ECDSA keypair (PKCS#1 PEM) | *(ignored, use `curve`)* | TLS certificates, JWT signing (ES256/ES384/ES512) |
| `ed25519` | Ed25519 keypair (PKCS#1 PEM) | *(ignored, fixed 256-bit)* | SSH keys, modern signing |

> **Note:** Kubernetes stores all secret data Base64-encoded. The `bytes` type generates raw bytes which are then Base64-encoded by Kubernetes when stored.

#### Keypair Types (rsa, ecdsa, ed25519)

For keypair types, the operator generates **two Secret data entries** per field:

| Entry | Content |
|-------|---------|
| `<field>` | Private Key in PEM format |
| `<field>.pub` | Public Key in PEM format |

All keys are output in **PKCS#1 PEM** format:
- RSA: `BEGIN RSA PRIVATE KEY` / `BEGIN RSA PUBLIC KEY`
- ECDSA: `BEGIN EC PRIVATE KEY` / `BEGIN PUBLIC KEY`
- Ed25519: `BEGIN PRIVATE KEY` / `BEGIN PUBLIC KEY`

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

### Generate an RSA Keypair

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: tls-keypair
  annotations:
    iso.gtrfc.com/autogenerate: tls-key
    iso.gtrfc.com/type: rsa
    iso.gtrfc.com/length: "4096"
type: Opaque
```

Result:
- `tls-key`: RSA 4096-bit Private Key (PEM, PKCS#1)
- `tls-key.pub`: RSA Public Key (PEM)

### Generate an ECDSA Keypair

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: signing-keypair
  annotations:
    iso.gtrfc.com/autogenerate: signing-key
    iso.gtrfc.com/type: ecdsa
    iso.gtrfc.com/curve: "P-256"
type: Opaque
```

Result:
- `signing-key`: ECDSA P-256 Private Key (PEM, PKCS#1)
- `signing-key.pub`: ECDSA P-256 Public Key (PEM)

Supported curves:

| Curve | Security Level | JWT Algorithm |
|-------|---------------|---------------|
| `P-256` (default) | ~RSA 3072 | ES256 |
| `P-384` | ~RSA 7680 | ES384 |
| `P-521` | ~RSA 15360 | ES512 |

### Generate an Ed25519 Keypair

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ssh-keypair
  annotations:
    iso.gtrfc.com/autogenerate: ssh-key
    iso.gtrfc.com/type: ed25519
type: Opaque
```

Result:
- `ssh-key`: Ed25519 Private Key (PEM)
- `ssh-key.pub`: Ed25519 Public Key (PEM)

> **Note:** Ed25519 keys have a fixed size (256-bit). The `length` and `curve` annotations are ignored for this type.

### Mixed: Passwords, RSA, ECDSA, and Ed25519

Generate different types of secrets in a single Secret resource:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mixed-credentials
  annotations:
    iso.gtrfc.com/autogenerate: password,tls-key,signing-key,ssh-key
    iso.gtrfc.com/type: string
    iso.gtrfc.com/length: "32"
    iso.gtrfc.com/type.tls-key: rsa
    iso.gtrfc.com/length.tls-key: "4096"
    iso.gtrfc.com/type.signing-key: ecdsa
    iso.gtrfc.com/curve.signing-key: "P-384"
    iso.gtrfc.com/type.ssh-key: ed25519
type: Opaque
```

Result:
- `password`: 32-character alphanumeric string
- `tls-key`: RSA 4096-bit Private Key (PEM)
- `tls-key.pub`: RSA 4096-bit Public Key (PEM)
- `signing-key`: ECDSA P-384 Private Key (PEM)
- `signing-key.pub`: ECDSA P-384 Public Key (PEM)
- `ssh-key`: Ed25519 Private Key (PEM)
- `ssh-key.pub`: Ed25519 Public Key (PEM)

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

    # Maintenance windows for secret rotation
    maintenanceWindows:
      enabled: false
      windows: []
```

Or via command line:

```bash
helm install internal-secrets-operator internal-secrets-operator/internal-secrets-operator \
  --set config.rotation.minInterval=10m \
  --set config.rotation.createEvents=true
```

## Maintenance Windows

Maintenance windows allow you to restrict secret rotation to specific time periods. This is useful for:

- **Avoiding disruptions** - Rotate secrets during low-traffic periods
- **Compliance requirements** - Restrict changes to approved maintenance windows
- **Coordinated updates** - Align rotation with deployment schedules

### How Maintenance Windows Work

1. When rotation is due, the operator checks if the current time is within any maintenance window
2. If inside a window: Rotation proceeds immediately
3. If outside all windows: Rotation is **deferred** until the next window starts
4. A Normal Event is created to inform you that rotation was deferred
5. The controller automatically reschedules reconciliation for the next window start

> **Note:** Initial secret generation (when a field has no value) is **NOT affected** by maintenance windows. Only rotation of existing values is restricted.

### Maintenance Window Configuration

Configure via Helm values:

```yaml
config:
  rotation:
    maintenanceWindows:
      enabled: true
      windows:
        - name: "weekend-night"
          days: ["saturday", "sunday"]
          startTime: "03:00"
          endTime: "05:00"
          timezone: "Europe/Berlin"
        - name: "weekday-maintenance"
          days: ["wednesday"]
          startTime: "02:00"
          endTime: "04:00"
          timezone: "UTC"
```

### Window Configuration Options

| Field | Description | Example |
|-------|-------------|---------|
| `name` | Descriptive name for logging | `"weekend-night"` |
| `days` | List of weekdays when the window is active | `["saturday", "sunday"]` |
| `startTime` | Start time in 24-hour format (HH:MM) | `"03:00"` |
| `endTime` | End time in 24-hour format (HH:MM) | `"05:00"` |
| `timezone` | IANA timezone identifier | `"Europe/Berlin"` |

#### Supported Day Names

`sunday`, `monday`, `tuesday`, `wednesday`, `thursday`, `friday`, `saturday` (case-insensitive)

#### Supported Timezones

Any IANA timezone is supported, for example:
- `UTC`
- `Europe/Berlin`, `Europe/London`, `Europe/Paris`
- `America/New_York`, `America/Los_Angeles`
- `Asia/Tokyo`, `Asia/Shanghai`
- `Australia/Sydney`

### Validation Rules

The operator validates maintenance window configuration at startup:

| Rule | Invalid Example | Error |
|------|-----------------|-------|
| `endTime` must be after `startTime` | `startTime: "05:00"`, `endTime: "03:00"` | Operator fails to start (CrashLoop) |
| At least one day required | `days: []` | Operator fails to start |
| Valid timezone required | `timezone: "Invalid/Zone"` | Operator fails to start |
| Valid time format | `startTime: "25:00"` | Operator fails to start |

### Example: Weekend-Only Rotation

```yaml
config:
  rotation:
    maintenanceWindows:
      enabled: true
      windows:
        - name: "weekend-night"
          days: ["saturday", "sunday"]
          startTime: "03:00"
          endTime: "05:00"
          timezone: "Europe/Berlin"
```

With this configuration, a secret with `rotate: "24h"` will:
- Wait until Saturday or Sunday between 03:00-05:00 Berlin time
- Rotate during the window
- Wait again for the next window if rotation is due outside the window

### Viewing Deferred Rotations

When rotation is deferred, a Normal Event is created:

```bash
kubectl describe secret rotating-secret
```

```
Events:
  Type    Reason           Age   From                        Message
  ----    ------           ----  ----                        -------
  Normal  RotationDeferred 5s    internal-secrets-operator   Rotation for field "password" deferred until next maintenance window at 2026-02-07T03:00:00Z (window: weekend-night)
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

## Secret Replication

The operator supports replicating Secrets across namespaces in two modes:
- **Pull-based**: A target Secret pulls data from a source Secret in another namespace
- **Push-based**: A source Secret automatically pushes its data to target namespaces

Both modes use a **mutual consent** security model and support automatic synchronization.

### Pull-based Replication

Pull-based replication requires **explicit consent from both sides**:

1. **Source Secret** must have `replicatable-from-namespaces` annotation (allowlist)
2. **Target Secret** must have `replicate-from` annotation pointing to the source

#### Example: Pull Replication

```yaml
---
# Source Secret in production namespace
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
  namespace: production
  annotations:
    # Allow staging namespace to replicate from this Secret
    iso.gtrfc.com/replicatable-from-namespaces: "staging"
type: Opaque
data:
  username: cHJvZHVzZXI=  # produser
  password: cHJvZHBhc3M=  # prodpass

---
# Target Secret in staging namespace
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
  namespace: staging
  annotations:
    # Pull data from production/db-credentials
    iso.gtrfc.com/replicate-from: "production/db-credentials"
type: Opaque
# data will be automatically populated
```

#### Glob Pattern Matching

The `replicatable-from-namespaces` annotation supports glob patterns:

```yaml
annotations:
  # Allow specific namespaces
  iso.gtrfc.com/replicatable-from-namespaces: "staging,development"

  # Allow all namespaces matching pattern
  iso.gtrfc.com/replicatable-from-namespaces: "env-*,namespace-[0-9]*"

  # Allow ALL namespaces
  iso.gtrfc.com/replicatable-from-namespaces: "*"
```

**Supported glob patterns:**
- `*` - matches any sequence of characters
- `?` - matches any single character
- `[abc]` - matches any character in the set (a, b, or c)
- `[a-z]` - matches any character in the range (a through z)
- `[0-9]` - matches any digit

#### Pull Replication Behavior

- ✅ Target automatically syncs when source changes
- ✅ If source is deleted, target keeps last known data (snapshot)
- ✅ Existing data in target is overwritten (replicated data wins)
- ✅ Replication only occurs with mutual consent (both annotations match)
- ❌ Target cannot replicate from multiple sources (one source per target)

### Push-based Replication

Push-based replication automatically creates and maintains Secrets in target namespaces.

#### Example: Push Replication

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
  namespace: production
  annotations:
    # Push this Secret to staging and development namespaces
    iso.gtrfc.com/replicate-to: "staging,development"
type: Opaque
data:
  app-id: YXBwLTEyMzQ1  # app-12345
  app-secret: c2VjcmV0a2V5  # secretkey
```

This will automatically create `app-secret` in both `staging` and `development` namespaces.

#### Push Replication Behavior

- ✅ Automatically creates Secrets in target namespaces
- ✅ Targets automatically sync when source changes
- ✅ Pushed Secrets have `replicated-from` annotation for tracking
- ✅ When source is deleted, all pushed Secrets are automatically cleaned up
- ⚠️ If target exists without `replicated-from` annotation: Skipped (Warning Event)
- ✅ If target exists with matching `replicated-from`: Updated

### Replication Annotations

| Annotation | Used By | Description | Example |
|------------|---------|-------------|---------|
| `replicatable-from-namespaces` | Source (pull) | Allowlist of namespaces that can pull from this Secret | `"staging,dev"`, `"env-*"`, `"*"` |
| `replicate-from` | Target (pull) | Source Secret to pull data from | `"production/db-credentials"` |
| `replicate-to` | Source (push) | Target namespaces to push this Secret to | `"staging,development"` |
| `replicated-from` | Target (auto) | Indicates this Secret was replicated (set by operator) | `"production/app-secret"` |
| `last-replicated-at` | Target (auto) | Timestamp of last replication (set by operator) | `"2025-12-05T10:00:00Z"` |

### Combining Generation and Replication

You can combine secret generation with replication:

#### ✅ Valid: Generate and Allow Pull

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: api-credentials
  namespace: production
  annotations:
    # Generate API key automatically
    iso.gtrfc.com/autogenerate: "api-key"
    iso.gtrfc.com/length: "32"

    # Allow other namespaces to pull
    iso.gtrfc.com/replicatable-from-namespaces: "staging,development"
type: Opaque
```

#### ✅ Valid: Generate and Push

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: encryption-keys
  namespace: security
  annotations:
    # Generate encryption keys
    iso.gtrfc.com/autogenerate: "master-key,data-key"
    iso.gtrfc.com/type: "bytes"
    iso.gtrfc.com/length: "32"

    # Push to application namespaces
    iso.gtrfc.com/replicate-to: "app-1,app-2,app-3"
type: Opaque
```

#### ❌ Invalid: Generate and Pull (Conflicting Features)

```yaml
# This will NOT work and will generate a Warning Event
apiVersion: v1
kind: Secret
metadata:
  name: invalid-secret
  namespace: default
  annotations:
    # ERROR: Cannot use both autogenerate and replicate-from
    iso.gtrfc.com/autogenerate: "password"
    iso.gtrfc.com/replicate-from: "other-ns/other-secret"
type: Opaque
```

### Replication Examples

See the [replication examples](config/samples/) for more:
- [Pull-based replication](config/samples/secret_pull_replication.yaml)
- [Push-based replication](config/samples/secret_push_replication.yaml)
- [Combined generation + replication](config/samples/secret_combined_generate_replicate.yaml)

### Security Considerations

1. **Mutual Consent**: Pull replication requires both source and target to explicitly allow it
2. **RBAC**: The operator needs `create` and `delete` permissions for push-based replication
3. **Namespace Access**: Control operator access via RBAC (ClusterRoleBinding or manual RoleBindings)
4. **Audit Trail**: All replicated Secrets have `replicated-from` annotation for tracking
5. **Events**: The operator creates Warning Events when replication fails

### Troubleshooting Replication

Check Secret events for replication errors:

```bash
kubectl describe secret my-secret
```

Common issues:
- **Replication denied**: Target namespace not in source allowlist
- **Source not found**: Check source namespace and name in `replicate-from`
- **Push failed**: Target Secret exists without `replicated-from` annotation
- **Conflicting features**: Both `autogenerate` and `replicate-from` annotations present

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
    # Default generation type: "string", "bytes", "rsa", "ecdsa", or "ed25519"
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
  # Generation type: "string", "bytes", "rsa", "ecdsa", or "ed25519"
  # - string: Generates alphanumeric characters (configurable charset)
  # - bytes: Generates raw random bytes
  # - rsa: Generates RSA keypair in PKCS#1 PEM format
  # - ecdsa: Generates ECDSA keypair in PKCS#1 PEM format
  # - ed25519: Generates Ed25519 keypair in PKCS#1 PEM format
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

features:
  # Enable automatic secret value generation
  secretGenerator: true

  # Enable secret replication across namespaces
  secretReplicator: true
```

### Configuration Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `defaults.type` | string | `string` | Default generation type. Valid values: `string`, `bytes`, `rsa`, `ecdsa`, `ed25519` |
| `defaults.length` | integer | `32` | Default length for generated values (must be > 0) |
| `defaults.string.uppercase` | boolean | `true` | Include uppercase letters (A-Z) in generated strings |
| `defaults.string.lowercase` | boolean | `true` | Include lowercase letters (a-z) in generated strings |
| `defaults.string.numbers` | boolean | `true` | Include numbers (0-9) in generated strings |
| `defaults.string.specialChars` | boolean | `false` | Include special characters in generated strings |
| `defaults.string.allowedSpecialChars` | string | `!@#$%^&*()_+-=[]{}|;:,.<>?` | Which special characters to use when `specialChars` is enabled |
| `rotation.minInterval` | duration | `5m` | Minimum allowed rotation interval. Rotation intervals below this value trigger a warning and use `minInterval` instead |
| `rotation.createEvents` | boolean | `false` | Create Normal Events when secrets are rotated. Useful for auditing |
| `features.secretGenerator` | boolean | `true` | Enable automatic secret value generation feature |
| `features.secretReplicator` | boolean | `true` | Enable secret replication across namespaces feature |

### Validation Rules

The operator validates the configuration at startup and will fail to start if:

1. **Invalid type**: `defaults.type` must be one of `string`, `bytes`, `rsa`, `ecdsa`, or `ed25519`
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