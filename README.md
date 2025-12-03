# Kubernetes Secret Operator

[![Build Status](https://github.com/guided-traffic/k8s-secret-operator/actions/workflows/release.yml/badge.svg)](https://github.com/guided-traffic/k8s-secret-operator/actions)
[![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/guided-traffic/k8s-secret-operator/main/.github/badges/coverage.json)](https://github.com/guided-traffic/k8s-secret-operator)
[![Go Report Card](https://goreportcard.com/badge/github.com/guided-traffic/k8s-secret-operator)](https://goreportcard.com/report/github.com/guided-traffic/k8s-secret-operator)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A Kubernetes operator that automatically generates random secret values. Use it for auto-generating random credentials for applications running on Kubernetes.

## Features

- 🔐 **Automatic Secret Generation** - Automatically generates cryptographically secure random values for Kubernetes Secrets
- 🎯 **Annotation-Based** - Simple annotation-based configuration, no CRDs required
-  **Configurable Length** - Customize the length of generated secrets
- 🔢 **Multiple Types** - Support for string and bytes generation
- ✅ **Idempotent** - Only generates values for empty fields, preserves existing data

## Quick Start

### Installation

#### Using Helm

```bash
helm repo add k8s-secret-operator https://guided-traffic.github.io/k8s-secret-operator
helm install k8s-secret-operator k8s-secret-operator/k8s-secret-operator
```

#### Using Kustomize

```bash
kubectl apply -k https://github.com/guided-traffic/k8s-secret-operator/config/default
```

### Usage

Create a Secret with the `autogenerate` annotation:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: example-secret
  annotations:
    secgen.gtrfc.com/autogenerate: password
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
    secgen.gtrfc.com/autogenerate: password
    secgen.gtrfc.com/type: string
    secgen.gtrfc.com/generated-at: "2025-12-03T10:00:00+01:00"
type: Opaque
data:
  username: c29tZXVzZXI=
  password: TWVwSU83L2huNXBralNTMHFwU3VKSkkwNmN4NmRpNTBBcVpuVDlLOQ==
```

## Configuration

### Annotations

All annotations use the prefix `secgen.gtrfc.com/`:

| Annotation | Description | Default |
|------------|-------------|---------|
| `autogenerate` | Comma-separated list of field names to auto-generate | *required* |
| `type` | Type of generated value: `string`, `bytes` | `string` |
| `length` | Length of generated string | `32` |

### Regenerating Secrets

The operator respects existing values and will **not** overwrite them. To regenerate a secret value, you have two options:

#### Option 1: Delete and recreate the Secret

```bash
kubectl delete secret my-secret
kubectl apply -f my-secret.yaml
```

#### Option 2: Delete specific keys from the Secret

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

### Examples

#### Generate multiple fields

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: multi-field-secret
  annotations:
    secgen.gtrfc.com/autogenerate: password,api-key,token
type: Opaque
```

#### Custom length

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: custom-length-secret
  annotations:
    secgen.gtrfc.com/autogenerate: password
    secgen.gtrfc.com/length: "64"
type: Opaque
```

#### Generate raw bytes (e.g., for encryption keys)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: bytes-secret
  annotations:
    secgen.gtrfc.com/autogenerate: encryption-key
    secgen.gtrfc.com/type: bytes
    secgen.gtrfc.com/length: "32"
type: Opaque
```

## Development

### Prerequisites

- Go 1.21+
- Docker
- kubectl
- Access to a Kubernetes cluster (or kind/minikube for local development)

### Building

```bash
# Build the binary
make build

# Build the Docker image
make docker-build

# Run tests
make test

# Run linter
make lint
```

### Running Locally

```bash
# Run against your current kubeconfig context
make run
```

### Testing with Kind

```bash
# Create a kind cluster
kind create cluster

# Deploy the operator
make deploy

# Apply a sample secret
kubectl apply -f config/samples/secret_example.yaml

# Check the result
kubectl get secret example-secret -o yaml
```

## Architecture

The operator follows the standard Kubernetes controller pattern:

```
┌─────────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                        │
│  ┌───────────────┐       ┌──────────────────────────────┐  │
│  │    Secret     │       │    Secret Operator    │  │
│  │  (with anno-  │◄─────►│  ┌────────────────────────┐  │
│  │   tations)    │       │  │   Secret Controller    │  │
│  └───────────────┘       │  │   - Watch Secrets      │  │
│                          │  │   - Filter by anno.    │  │
│                          │  │   - Reconcile          │  │
│                          │  └────────────────────────┘  │
│                          │  ┌────────────────────────┐  │
│                          │  │   Value Generator      │  │
│                          │  │   - crypto/rand        │  │
│                          │  │   - Multiple types     │  │
│                          │  └────────────────────────┘  │
│                          └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## RBAC and Namespace Access

By default, the operator is deployed with a **ClusterRoleBinding**, giving it access to Secrets in **all namespaces**. This is convenient for most use cases but may not meet your security requirements.

### Restricting to Specific Namespaces

For environments where you need fine-grained control over which namespaces the operator can access, you can disable the ClusterRoleBinding and create RoleBindings manually in specific namespaces.

#### Step 1: Disable ClusterRoleBinding

Install or upgrade the Helm chart with the ClusterRoleBinding disabled:

```bash
helm install k8s-secret-operator k8s-secret-operator/k8s-secret-operator \
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
  name: k8s-secret-operator
  namespace: my-app-namespace  # The namespace to grant access to
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: k8s-secret-operator  # Must match the ClusterRole name from the Helm release
subjects:
  - kind: ServiceAccount
    name: k8s-secret-operator  # Must match the ServiceAccount name from the Helm release
    namespace: k8s-secret-operator  # The namespace where the operator is deployed
```

> **Note:** If you customized the Helm release name or used `fullnameOverride`, adjust the ClusterRole and ServiceAccount names accordingly.

#### Example: Granting Access to Multiple Namespaces

To grant access to `production`, `staging`, and `development` namespaces:

```bash
# Create RoleBindings in each namespace
for ns in production staging development; do
  kubectl create rolebinding k8s-secret-operator \
    --clusterrole=k8s-secret-operator \
    --serviceaccount=k8s-secret-operator:k8s-secret-operator \
    --namespace=$ns
done
```

Or using a manifest:

```yaml
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: k8s-secret-operator
  namespace: production
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: k8s-secret-operator
subjects:
  - kind: ServiceAccount
    name: k8s-secret-operator
    namespace: k8s-secret-operator
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: k8s-secret-operator
  namespace: staging
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: k8s-secret-operator
subjects:
  - kind: ServiceAccount
    name: k8s-secret-operator
    namespace: k8s-secret-operator
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: k8s-secret-operator
  namespace: development
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: k8s-secret-operator
subjects:
  - kind: ServiceAccount
    name: k8s-secret-operator
    namespace: k8s-secret-operator
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