# internal-secrets-operator Helm Chart

A Kubernetes controller that automatically generates random secret values for Secrets with specific annotations.

For usage documentation and annotation reference, see the [main README](../../../README.md).

## Installation

```bash
helm install internal-secrets-operator ./deploy/helm/internal-secrets-operator
```

## Values

### General

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `replicaCount` | int | `1` | Number of controller replicas |
| `nameOverride` | string | `""` | Override the chart name |
| `fullnameOverride` | string | `""` | Override the full release name |

### Image

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `image.repository` | string | `"docker.io/guidedtraffic/internal-secrets-operator"` | Container image repository |
| `image.pullPolicy` | string | `"IfNotPresent"` | Image pull policy |
| `image.tag` | string | `""` | Image tag (defaults to chart appVersion) |
| `imagePullSecrets` | list | `[]` | Image pull secrets for private registries |

### Controller

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `controller.leaderElection` | bool | `true` | Enable leader election for high availability |

### Operator Configuration

The `config` section is written directly to a ConfigMap and mounted as the operator's configuration file at `/etc/secret-operator/config.yaml`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `config.defaults.type` | string | `"string"` | Default generation type: `string` or `bytes` |
| `config.defaults.length` | int | `32` | Default length for generated values |
| `config.defaults.string.uppercase` | bool | `true` | Include uppercase letters (A-Z) |
| `config.defaults.string.lowercase` | bool | `true` | Include lowercase letters (a-z) |
| `config.defaults.string.numbers` | bool | `true` | Include numbers (0-9) |
| `config.defaults.string.specialChars` | bool | `false` | Include special characters |
| `config.defaults.string.allowedSpecialChars` | string | `"!@#$%^&*()_+-=[]{}|;:,.<>?"` | Which special characters to use |

> **Note:** At least one of `uppercase`, `lowercase`, `numbers`, or `specialChars` must be `true`.

### Rotation Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `config.rotation.minInterval` | string | `"5m"` | Minimum allowed rotation interval (prevents tight loops) |
| `config.rotation.createEvents` | bool | `false` | Create Normal Events when secrets are rotated |

### Maintenance Windows

Maintenance windows allow you to restrict secret rotation to specific time periods. This is useful to avoid rotations during peak hours.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `config.rotation.maintenanceWindows.enabled` | bool | `false` | Enable maintenance windows for rotation |
| `config.rotation.maintenanceWindows.windows` | list | `[]` | List of maintenance window definitions |

Each window in the `windows` list supports:

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Name of the window (for logging) |
| `days` | list | Days when rotation is allowed: `sunday`, `monday`, `tuesday`, `wednesday`, `thursday`, `friday`, `saturday` |
| `startTime` | string | Start time in `HH:MM` format (24-hour) |
| `endTime` | string | End time in `HH:MM` format (24-hour). Must be after `startTime` |
| `timezone` | string | IANA timezone (e.g., `Europe/Berlin`, `UTC`, `America/New_York`) |

**Example Configuration:**

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

**Behavior:**
- When maintenance windows are enabled, rotation only occurs during the defined time windows
- Outside of windows, a Normal Event is created indicating rotation is deferred
- The controller automatically requeues to check again when the next window starts
- Initial secret generation (when a secret has no value yet) is NOT affected by maintenance windows
- If `endTime` is before or equal to `startTime`, the operator will fail to start (CrashLoop)

### Feature Toggles

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `config.features.secretGenerator` | bool | `true` | Enable automatic secret value generation |
| `config.features.secretReplicator` | bool | `true` | Enable secret replication across namespaces |

### Service Account

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `serviceAccount.create` | bool | `true` | Create a service account |
| `serviceAccount.automount` | bool | `true` | Automount the service account token |
| `serviceAccount.annotations` | object | `{}` | Annotations for the service account |
| `serviceAccount.name` | string | `""` | Service account name (generated if not set) |

### RBAC

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `rbac.create` | bool | `true` | Create RBAC resources (ClusterRole, etc.) |
| `rbac.clusterRoleBinding.enabled` | bool | `true` | Create a ClusterRoleBinding for cluster-wide access |

#### Restricting Namespace Access

By default, the operator has access to Secrets in all namespaces via a ClusterRoleBinding. To restrict access to specific namespaces:

1. Disable the ClusterRoleBinding:
   ```yaml
   rbac:
     clusterRoleBinding:
       enabled: false
   ```

2. Manually create RoleBindings in each namespace where the operator should work:
   ```yaml
   apiVersion: rbac.authorization.k8s.io/v1
   kind: RoleBinding
   metadata:
     name: internal-secrets-operator
     namespace: my-namespace
   roleRef:
     apiGroup: rbac.authorization.k8s.io
     kind: ClusterRole
     name: internal-secrets-operator  # Use the ClusterRole created by the chart
   subjects:
     - kind: ServiceAccount
       name: internal-secrets-operator
       namespace: default  # Namespace where the operator is installed
   ```

### Pod Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `podAnnotations` | object | `{}` | Annotations for the pods |
| `podLabels` | object | `{}` | Extra labels for pods (not added to selector). Useful for `sidecar.istio.io/inject`, etc. |
| `podSecurityContext.runAsNonRoot` | bool | `true` | Run as non-root user |
| `podSecurityContext.seccompProfile.type` | string | `"RuntimeDefault"` | Seccomp profile type |

### Container Security Context

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `securityContext.allowPrivilegeEscalation` | bool | `false` | Disallow privilege escalation |
| `securityContext.capabilities.drop` | list | `["ALL"]` | Drop all capabilities |
| `securityContext.readOnlyRootFilesystem` | bool | `true` | Read-only root filesystem |
| `securityContext.runAsNonRoot` | bool | `true` | Run as non-root |
| `securityContext.runAsUser` | int | `65532` | User ID to run as |

### Service & Health Probes

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `service.type` | string | `"ClusterIP"` | Service type for metrics endpoint |
| `service.port` | int | `8080` | Metrics service port |
| `healthProbe.port` | int | `8081` | Health probe port |

### Probes

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `livenessProbe.httpGet.path` | string | `"/healthz"` | Liveness probe path |
| `livenessProbe.httpGet.port` | string | `"health"` | Liveness probe port |
| `livenessProbe.initialDelaySeconds` | int | `15` | Initial delay before liveness probe |
| `livenessProbe.periodSeconds` | int | `20` | Period between liveness probes |
| `readinessProbe.httpGet.path` | string | `"/readyz"` | Readiness probe path |
| `readinessProbe.httpGet.port` | string | `"health"` | Readiness probe port |
| `readinessProbe.initialDelaySeconds` | int | `5` | Initial delay before readiness probe |
| `readinessProbe.periodSeconds` | int | `10` | Period between readiness probes |

### Resources

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `resources.limits.cpu` | string | `"500m"` | CPU limit |
| `resources.limits.memory` | string | `"128Mi"` | Memory limit |
| `resources.requests.cpu` | string | `"10m"` | CPU request |
| `resources.requests.memory` | string | `"64Mi"` | Memory request |

### Autoscaling

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `autoscaling.enabled` | bool | `false` | Enable horizontal pod autoscaling |
| `autoscaling.minReplicas` | int | `1` | Minimum replicas |
| `autoscaling.maxReplicas` | int | `3` | Maximum replicas |
| `autoscaling.targetCPUUtilizationPercentage` | int | `80` | Target CPU utilization |

### Volumes

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `volumes` | list | `[]` | Additional volumes for the deployment |
| `volumeMounts` | list | `[]` | Additional volume mounts for the container |

### Scheduling

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `nodeSelector` | object | `{}` | Node selector for pod scheduling |
| `tolerations` | list | `[]` | Tolerations for pod scheduling |
| `affinity` | object | `{}` | Affinity rules for pod scheduling |

### Monitoring

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `serviceMonitor.enabled` | bool | `false` | Create a ServiceMonitor for Prometheus Operator |
| `serviceMonitor.interval` | string | `"30s"` | Scrape interval |
| `serviceMonitor.scrapeTimeout` | string | `"10s"` | Scrape timeout |
| `serviceMonitor.labels` | object | `{}` | Additional labels for the ServiceMonitor |

## Example Values

### Minimal Configuration

```yaml
# Use defaults
```

### Production Configuration

```yaml
replicaCount: 2

controller:
  leaderElection: true

config:
  defaults:
    type: string
    length: 48
    string:
      uppercase: true
      lowercase: true
      numbers: true
      specialChars: true
      allowedSpecialChars: "!@#$%^&*"

resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi

serviceMonitor:
  enabled: true
  labels:
    release: prometheus

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: internal-secrets-operator
          topologyKey: kubernetes.io/hostname
```

### Restricted Namespace Access

```yaml
rbac:
  clusterRoleBinding:
    enabled: false

# Then manually create RoleBindings in allowed namespaces
```

### With Istio Sidecar Disabled

```yaml
podLabels:
  sidecar.istio.io/inject: "false"
```
