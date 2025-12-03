# Kubernetes Secret Operator

[![Build Status](https://github.com/guided-traffic/k8s-secret-operator/actions/workflows/build.yml/badge.svg)](https://github.com/guided-traffic/k8s-secret-operator/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/guided-traffic/k8s-secret-operator)](https://goreportcard.com/report/github.com/guided-traffic/k8s-secret-operator)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A Kubernetes operator that automatically generates random secret values. Use it for auto-generating random credentials for applications running on Kubernetes.

## Features

- 🔐 **Automatic Secret Generation** - Automatically generates cryptographically secure random values for Kubernetes Secrets
- 🎯 **Annotation-Based** - Simple annotation-based configuration, no CRDs required
- 🔄 **Regeneration Support** - Force regeneration of secrets when needed
- 📏 **Configurable Length** - Customize the length of generated secrets
- 🔢 **Multiple Types** - Support for string, base64, UUID, and hex generation
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
    secgen.gtrfc.com/secure: "yes"
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
| `type` | Type of generated value: `string`, `base64`, `uuid`, `hex` | `string` |
| `length` | Length of generated string | `32` |
| `regenerate` | Set to `true` to force regeneration | - |

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

#### Generate UUID

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: uuid-secret
  annotations:
    secgen.gtrfc.com/autogenerate: client-id
    secgen.gtrfc.com/type: uuid
type: Opaque
```

#### Force regeneration

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: regenerate-secret
  annotations:
    secgen.gtrfc.com/autogenerate: password
    secgen.gtrfc.com/regenerate: "true"
type: Opaque
data:
  password: b2xkLXBhc3N3b3Jk  # This will be replaced
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