//go:build e2e
// +build e2e

/*
Copyright 2025 Guided Traffic.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"context"
	"os"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	// AnnotationReplicatableFromNamespaces allowlist of namespaces that can replicate FROM this object
	AnnotationReplicatableFromNamespaces = AnnotationPrefix + "replicatable-from-namespaces"

	// AnnotationReplicateFrom source object to replicate data from (format: "namespace/name")
	AnnotationReplicateFrom = AnnotationPrefix + "replicate-from"

	// AnnotationReplicateTo push this secret to specified namespaces (comma-separated)
	AnnotationReplicateTo = AnnotationPrefix + "replicate-to"

	// AnnotationReplicatedFrom indicates this object was replicated from another object
	AnnotationReplicatedFrom = AnnotationPrefix + "replicated-from"

	// replSourceNamespace is the source namespace for replication E2E tests.
	// Must match globalPullBasedPermissions.fromNamespace in test/e2e/helm-values.yaml
	replSourceNamespace = "e2e-repl-source"

	// replTargetNamespace is the target namespace for replication E2E tests.
	// Must match globalPullBasedPermissions.toNamespace in test/e2e/helm-values.yaml
	replTargetNamespace = "e2e-repl-target"

	// globalPermNamePrefix is the object name prefix allowed by the global
	// pull-based permission (validationPattern "global-*" in helm-values.yaml)
	globalPermNamePrefix = "global-"

	// operatorNameLabel is the app.kubernetes.io/name label value set by the Helm chart
	operatorNameLabel = "internal-secrets-operator"
)

// operatorNamespace returns the namespace the operator was installed into
// (see Makefile target e2e-local)
func operatorNamespace() string {
	if ns := os.Getenv("OPERATOR_NAMESPACE"); ns != "" {
		return ns
	}
	return "internal-secrets-operator-system"
}

// ensureNamespace creates a namespace if it does not exist yet
func ensureNamespace(ctx context.Context, t *testing.T, name string) {
	t.Helper()
	_, err := clientset.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}, metav1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		t.Fatalf("Failed to create namespace %s: %v", name, err)
	}
}

// ensureReplicationNamespaces creates the fixed source/target namespaces used
// by the replication E2E tests
func ensureReplicationNamespaces(ctx context.Context, t *testing.T) {
	t.Helper()
	ensureNamespace(ctx, t, replSourceNamespace)
	ensureNamespace(ctx, t, replTargetNamespace)
}

func deleteSecretIgnoreNotFound(t *testing.T, namespace, name string) {
	t.Helper()
	err := clientset.CoreV1().Secrets(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		t.Logf("Warning: failed to delete secret %s/%s: %v", namespace, name, err)
	}
}

func deleteConfigMapIgnoreNotFound(t *testing.T, namespace, name string) {
	t.Helper()
	err := clientset.CoreV1().ConfigMaps(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		t.Logf("Warning: failed to delete configmap %s/%s: %v", namespace, name, err)
	}
}

// waitForSecretCondition polls the secret until the condition returns true
func waitForSecretCondition(ctx context.Context, namespace, name string, condition func(*corev1.Secret) bool) (*corev1.Secret, error) {
	var result *corev1.Secret
	err := wait.PollUntilContextTimeout(ctx, pollInterval, pollTimeout, true, func(ctx context.Context) (bool, error) {
		s, err := clientset.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		if condition(s) {
			result = s
			return true, nil
		}
		return false, nil
	})
	return result, err
}

// waitForConfigMapCondition polls the configmap until the condition returns true
func waitForConfigMapCondition(ctx context.Context, namespace, name string, condition func(*corev1.ConfigMap) bool) (*corev1.ConfigMap, error) {
	var result *corev1.ConfigMap
	err := wait.PollUntilContextTimeout(ctx, pollInterval, pollTimeout, true, func(ctx context.Context) (bool, error) {
		cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		if condition(cm) {
			result = cm
			return true, nil
		}
		return false, nil
	})
	return result, err
}

// waitForWarningEvent polls until a Warning event with the given reason exists
// for the object, and returns the event note
func waitForWarningEvent(ctx context.Context, namespace, objectName, objectKind, reason string) (string, error) {
	var note string
	err := wait.PollUntilContextTimeout(ctx, pollInterval, pollTimeout, true, func(ctx context.Context) (bool, error) {
		events, err := clientset.EventsV1().Events(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, nil
		}
		for _, event := range events.Items {
			if event.Regarding.Name == objectName && event.Regarding.Kind == objectKind &&
				event.Type == "Warning" && event.Reason == reason {
				note = event.Note
				return true, nil
			}
		}
		return false, nil
	})
	return note, err
}

// TestOperatorHelmDeployment verifies that the Helm-installed operator is
// healthy: deployment ready, pod running, and the config file rendered from
// Helm values contains the global pull-based permissions.
func TestOperatorHelmDeployment(t *testing.T) {
	ctx := context.Background()
	ns := operatorNamespace()
	labelSelector := "app.kubernetes.io/name=" + operatorNameLabel

	// Deployment must exist and become ready
	deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		t.Fatalf("Failed to list deployments in %s: %v", ns, err)
	}
	if len(deployments.Items) != 1 {
		t.Fatalf("Expected exactly 1 operator deployment in %s, got %d", ns, len(deployments.Items))
	}
	deploymentName := deployments.Items[0].Name

	err = wait.PollUntilContextTimeout(ctx, pollInterval, pollTimeout, true, func(ctx context.Context) (bool, error) {
		d, err := clientset.AppsV1().Deployments(ns).Get(ctx, deploymentName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		want := int32(1)
		if d.Spec.Replicas != nil {
			want = *d.Spec.Replicas
		}
		return d.Status.ReadyReplicas == want && d.Status.UpdatedReplicas == want, nil
	})
	if err != nil {
		t.Fatalf("Timeout waiting for operator deployment %s/%s to become ready: %v", ns, deploymentName, err)
	}

	// Pod must be running and ready
	pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		t.Fatalf("Failed to list operator pods: %v", err)
	}
	if len(pods.Items) == 0 {
		t.Fatal("No operator pods found")
	}
	for _, pod := range pods.Items {
		if pod.Status.Phase != corev1.PodRunning {
			t.Errorf("Pod %s is in phase %s, expected Running", pod.Name, pod.Status.Phase)
		}
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.RestartCount > 0 {
				t.Logf("Warning: container %s in pod %s restarted %d times", cs.Name, pod.Name, cs.RestartCount)
			}
		}
	}

	// The rendered operator config must contain the global pull-based permissions
	configMapName := deploymentName + "-config"
	cm, err := clientset.CoreV1().ConfigMaps(ns).Get(ctx, configMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get operator config ConfigMap %s/%s: %v", ns, configMapName, err)
	}
	configYAML := cm.Data["config.yaml"]
	if !strings.Contains(configYAML, "globalPullBasedPermissions") {
		t.Errorf("Operator config does not contain globalPullBasedPermissions:\n%s", configYAML)
	}
	if !strings.Contains(configYAML, replSourceNamespace) || !strings.Contains(configYAML, replTargetNamespace) {
		t.Errorf("Operator config does not contain the E2E replication namespaces:\n%s", configYAML)
	}

	t.Logf("Operator deployment %s/%s is healthy, config contains global pull-based permissions", ns, deploymentName)
}

// TestSecretPullReplicationWithAnnotation verifies pull-based Secret
// replication via mutual consent (source allowlist annotation), including
// sync after a source change.
func TestSecretPullReplicationWithAnnotation(t *testing.T) {
	ctx := context.Background()
	ensureReplicationNamespaces(ctx, t)

	const name = "e2e-pull-annotation"
	defer deleteSecretIgnoreNotFound(t, replSourceNamespace, name)
	defer deleteSecretIgnoreNotFound(t, replTargetNamespace, name)

	source := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: replSourceNamespace,
			Annotations: map[string]string{
				AnnotationReplicatableFromNamespaces: replTargetNamespace,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"username": []byte("produser"),
			"password": []byte("prodpass"),
		},
	}
	if _, err := clientset.CoreV1().Secrets(replSourceNamespace).Create(ctx, source, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Failed to create source secret: %v", err)
	}

	target := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: replTargetNamespace,
			Annotations: map[string]string{
				AnnotationReplicateFrom: replSourceNamespace + "/" + name,
			},
		},
		Type: corev1.SecretTypeOpaque,
	}
	if _, err := clientset.CoreV1().Secrets(replTargetNamespace).Create(ctx, target, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Failed to create target secret: %v", err)
	}

	// Wait for replication
	replicated, err := waitForSecretCondition(ctx, replTargetNamespace, name, func(s *corev1.Secret) bool {
		return string(s.Data["password"]) == "prodpass"
	})
	if err != nil {
		t.Fatalf("Timeout waiting for pull replication: %v", err)
	}
	if string(replicated.Data["username"]) != "produser" {
		t.Errorf("username not replicated, got %q", string(replicated.Data["username"]))
	}
	if replicated.Annotations[AnnotationReplicatedFrom] != replSourceNamespace+"/"+name {
		t.Errorf("replicated-from annotation = %q, want %q", replicated.Annotations[AnnotationReplicatedFrom], replSourceNamespace+"/"+name)
	}

	// Update source, target must sync
	latest, err := clientset.CoreV1().Secrets(replSourceNamespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get source secret: %v", err)
	}
	latest.Data["password"] = []byte("rotated-pass")
	if _, err := clientset.CoreV1().Secrets(replSourceNamespace).Update(ctx, latest, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("Failed to update source secret: %v", err)
	}

	if _, err := waitForSecretCondition(ctx, replTargetNamespace, name, func(s *corev1.Secret) bool {
		return string(s.Data["password"]) == "rotated-pass"
	}); err != nil {
		t.Fatalf("Timeout waiting for target sync after source change: %v", err)
	}

	t.Log("Pull replication with annotation consent works, including source sync")
}

// TestSecretPullReplicationDenied verifies that without source consent and
// without a matching global permission no data is replicated and a Warning
// event is created on the target.
func TestSecretPullReplicationDenied(t *testing.T) {
	ctx := context.Background()
	ensureReplicationNamespaces(ctx, t)

	// Name does NOT match the global validationPattern "global-*"
	const name = "e2e-pull-denied"
	defer deleteSecretIgnoreNotFound(t, replSourceNamespace, name)
	defer deleteSecretIgnoreNotFound(t, replTargetNamespace, name)

	source := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: replSourceNamespace,
			// No allowlist annotation
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"password": []byte("topsecret")},
	}
	if _, err := clientset.CoreV1().Secrets(replSourceNamespace).Create(ctx, source, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Failed to create source secret: %v", err)
	}

	target := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: replTargetNamespace,
			Annotations: map[string]string{
				AnnotationReplicateFrom: replSourceNamespace + "/" + name,
			},
		},
		Type: corev1.SecretTypeOpaque,
	}
	if _, err := clientset.CoreV1().Secrets(replTargetNamespace).Create(ctx, target, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Failed to create target secret: %v", err)
	}

	// Warning event must appear on the target
	note, err := waitForWarningEvent(ctx, replTargetNamespace, name, "Secret", "ReplicationFailed")
	if err != nil {
		t.Fatalf("Timeout waiting for ReplicationFailed event: %v", err)
	}
	if !strings.Contains(note, "not allowed") {
		t.Errorf("Expected denial reason in event note, got: %s", note)
	}

	// Data must NOT be replicated
	current, err := clientset.CoreV1().Secrets(replTargetNamespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get target secret: %v", err)
	}
	if len(current.Data) > 0 {
		t.Errorf("Expected empty target secret, got data: %v", current.Data)
	}

	t.Log("Pull replication correctly denied without consent")
}

// TestSecretGlobalPullPermission verifies that a Secret whose name matches
// the global pull-based permission from the Helm values is replicated
// WITHOUT any annotation on the source object, and that the target syncs
// when the source changes.
func TestSecretGlobalPullPermission(t *testing.T) {
	ctx := context.Background()
	ensureReplicationNamespaces(ctx, t)

	name := globalPermNamePrefix + "db-credentials"
	defer deleteSecretIgnoreNotFound(t, replSourceNamespace, name)
	defer deleteSecretIgnoreNotFound(t, replTargetNamespace, name)

	// Source WITHOUT any replication annotation - permission comes from Helm values
	source := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: replSourceNamespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"password": []byte("global-pass")},
	}
	if _, err := clientset.CoreV1().Secrets(replSourceNamespace).Create(ctx, source, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Failed to create source secret: %v", err)
	}

	target := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: replTargetNamespace,
			Annotations: map[string]string{
				AnnotationReplicateFrom: replSourceNamespace + "/" + name,
			},
		},
		Type: corev1.SecretTypeOpaque,
	}
	if _, err := clientset.CoreV1().Secrets(replTargetNamespace).Create(ctx, target, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Failed to create target secret: %v", err)
	}

	replicated, err := waitForSecretCondition(ctx, replTargetNamespace, name, func(s *corev1.Secret) bool {
		return string(s.Data["password"]) == "global-pass"
	})
	if err != nil {
		t.Fatalf("Timeout waiting for replication via global permission: %v", err)
	}
	if replicated.Annotations[AnnotationReplicatedFrom] == "" {
		t.Error("Missing replicated-from annotation")
	}

	// Source change must sync (source watch must cover annotation-less global sources)
	latest, err := clientset.CoreV1().Secrets(replSourceNamespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get source secret: %v", err)
	}
	latest.Data["password"] = []byte("global-rotated")
	if _, err := clientset.CoreV1().Secrets(replSourceNamespace).Update(ctx, latest, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("Failed to update source secret: %v", err)
	}

	if _, err := waitForSecretCondition(ctx, replTargetNamespace, name, func(s *corev1.Secret) bool {
		return string(s.Data["password"]) == "global-rotated"
	}); err != nil {
		t.Fatalf("Timeout waiting for target sync after source change: %v", err)
	}

	t.Log("Global pull-based permission for Secrets works, including source sync")
}

// TestSecretPushReplication verifies push-based replication including cleanup
// of pushed Secrets when the source is deleted.
func TestSecretPushReplication(t *testing.T) {
	ctx := context.Background()
	ensureReplicationNamespaces(ctx, t)

	const name = "e2e-push"
	defer deleteSecretIgnoreNotFound(t, replSourceNamespace, name)
	defer deleteSecretIgnoreNotFound(t, replTargetNamespace, name)

	source := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: replSourceNamespace,
			Annotations: map[string]string{
				AnnotationReplicateTo: replTargetNamespace,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"api-key": []byte("pushed-key")},
	}
	if _, err := clientset.CoreV1().Secrets(replSourceNamespace).Create(ctx, source, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Failed to create source secret: %v", err)
	}

	// Pushed secret must appear in the target namespace
	pushed, err := waitForSecretCondition(ctx, replTargetNamespace, name, func(s *corev1.Secret) bool {
		return string(s.Data["api-key"]) == "pushed-key"
	})
	if err != nil {
		t.Fatalf("Timeout waiting for pushed secret: %v", err)
	}
	if pushed.Annotations[AnnotationReplicatedFrom] != replSourceNamespace+"/"+name {
		t.Errorf("replicated-from = %q, want %q", pushed.Annotations[AnnotationReplicatedFrom], replSourceNamespace+"/"+name)
	}

	// Deleting the source must clean up the pushed secret (finalizer logic)
	if err := clientset.CoreV1().Secrets(replSourceNamespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("Failed to delete source secret: %v", err)
	}

	err = wait.PollUntilContextTimeout(ctx, pollInterval, pollTimeout, true, func(ctx context.Context) (bool, error) {
		_, err := clientset.CoreV1().Secrets(replTargetNamespace).Get(ctx, name, metav1.GetOptions{})
		return errors.IsNotFound(err), nil
	})
	if err != nil {
		t.Fatalf("Timeout waiting for pushed secret cleanup after source deletion: %v", err)
	}

	t.Log("Push replication works, including cleanup on source deletion")
}

// TestConfigMapPullReplicationWithAnnotation verifies pull-based ConfigMap
// replication via mutual consent (source allowlist annotation).
func TestConfigMapPullReplicationWithAnnotation(t *testing.T) {
	ctx := context.Background()
	ensureReplicationNamespaces(ctx, t)

	const name = "e2e-cm-pull-annotation"
	defer deleteConfigMapIgnoreNotFound(t, replSourceNamespace, name)
	defer deleteConfigMapIgnoreNotFound(t, replTargetNamespace, name)

	source := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: replSourceNamespace,
			Annotations: map[string]string{
				AnnotationReplicatableFromNamespaces: replTargetNamespace,
			},
		},
		Data: map[string]string{"setting": "value-1"},
	}
	if _, err := clientset.CoreV1().ConfigMaps(replSourceNamespace).Create(ctx, source, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Failed to create source configmap: %v", err)
	}

	target := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: replTargetNamespace,
			Annotations: map[string]string{
				AnnotationReplicateFrom: replSourceNamespace + "/" + name,
			},
		},
	}
	if _, err := clientset.CoreV1().ConfigMaps(replTargetNamespace).Create(ctx, target, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Failed to create target configmap: %v", err)
	}

	if _, err := waitForConfigMapCondition(ctx, replTargetNamespace, name, func(cm *corev1.ConfigMap) bool {
		return cm.Data["setting"] == "value-1"
	}); err != nil {
		t.Fatalf("Timeout waiting for configmap pull replication: %v", err)
	}

	// Update source, target must sync
	latest, err := clientset.CoreV1().ConfigMaps(replSourceNamespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get source configmap: %v", err)
	}
	latest.Data["setting"] = "value-2"
	if _, err := clientset.CoreV1().ConfigMaps(replSourceNamespace).Update(ctx, latest, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("Failed to update source configmap: %v", err)
	}

	if _, err := waitForConfigMapCondition(ctx, replTargetNamespace, name, func(cm *corev1.ConfigMap) bool {
		return cm.Data["setting"] == "value-2"
	}); err != nil {
		t.Fatalf("Timeout waiting for configmap sync after source change: %v", err)
	}

	t.Log("ConfigMap pull replication with annotation consent works, including source sync")
}

// TestConfigMapGlobalPullPermission verifies that a ConfigMap matching the
// global pull-based permission from the Helm values is replicated without
// any annotation on the source, including binaryData.
func TestConfigMapGlobalPullPermission(t *testing.T) {
	ctx := context.Background()
	ensureReplicationNamespaces(ctx, t)

	name := globalPermNamePrefix + "ca-bundle"
	defer deleteConfigMapIgnoreNotFound(t, replSourceNamespace, name)
	defer deleteConfigMapIgnoreNotFound(t, replTargetNamespace, name)

	// Source WITHOUT any replication annotation
	source := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: replSourceNamespace,
		},
		Data:       map[string]string{"ca.crt": "cert-content"},
		BinaryData: map[string][]byte{"blob": {0xCA, 0xFE}},
	}
	if _, err := clientset.CoreV1().ConfigMaps(replSourceNamespace).Create(ctx, source, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Failed to create source configmap: %v", err)
	}

	target := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: replTargetNamespace,
			Annotations: map[string]string{
				AnnotationReplicateFrom: replSourceNamespace + "/" + name,
			},
		},
	}
	if _, err := clientset.CoreV1().ConfigMaps(replTargetNamespace).Create(ctx, target, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Failed to create target configmap: %v", err)
	}

	replicated, err := waitForConfigMapCondition(ctx, replTargetNamespace, name, func(cm *corev1.ConfigMap) bool {
		return cm.Data["ca.crt"] == "cert-content"
	})
	if err != nil {
		t.Fatalf("Timeout waiting for configmap replication via global permission: %v", err)
	}
	if string(replicated.BinaryData["blob"]) != string([]byte{0xCA, 0xFE}) {
		t.Errorf("binaryData not replicated, got: %v", replicated.BinaryData)
	}
	if replicated.Annotations[AnnotationReplicatedFrom] != replSourceNamespace+"/"+name {
		t.Errorf("replicated-from = %q, want %q", replicated.Annotations[AnnotationReplicatedFrom], replSourceNamespace+"/"+name)
	}

	t.Log("Global pull-based permission for ConfigMaps works, including binaryData")
}

// TestConfigMapPushReplication verifies push-based ConfigMap replication
// including cleanup of pushed ConfigMaps when the source is deleted.
func TestConfigMapPushReplication(t *testing.T) {
	ctx := context.Background()
	ensureReplicationNamespaces(ctx, t)

	const name = "e2e-cm-push"
	defer deleteConfigMapIgnoreNotFound(t, replSourceNamespace, name)
	defer deleteConfigMapIgnoreNotFound(t, replTargetNamespace, name)

	source := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: replSourceNamespace,
			Annotations: map[string]string{
				AnnotationReplicateTo: replTargetNamespace,
			},
		},
		Data:       map[string]string{"setting": "pushed-value"},
		BinaryData: map[string][]byte{"blob": {0x0B, 0x0E}},
	}
	if _, err := clientset.CoreV1().ConfigMaps(replSourceNamespace).Create(ctx, source, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Failed to create source configmap: %v", err)
	}

	// Pushed ConfigMap must appear in the target namespace
	pushed, err := waitForConfigMapCondition(ctx, replTargetNamespace, name, func(cm *corev1.ConfigMap) bool {
		return cm.Data["setting"] == "pushed-value"
	})
	if err != nil {
		t.Fatalf("Timeout waiting for pushed configmap: %v", err)
	}
	if pushed.Annotations[AnnotationReplicatedFrom] != replSourceNamespace+"/"+name {
		t.Errorf("replicated-from = %q, want %q", pushed.Annotations[AnnotationReplicatedFrom], replSourceNamespace+"/"+name)
	}
	if string(pushed.BinaryData["blob"]) != string([]byte{0x0B, 0x0E}) {
		t.Errorf("binaryData not pushed, got: %v", pushed.BinaryData)
	}

	// Source change must sync to the pushed target
	latest, err := clientset.CoreV1().ConfigMaps(replSourceNamespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get source configmap: %v", err)
	}
	latest.Data["setting"] = "pushed-value-2"
	if _, err := clientset.CoreV1().ConfigMaps(replSourceNamespace).Update(ctx, latest, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("Failed to update source configmap: %v", err)
	}
	if _, err := waitForConfigMapCondition(ctx, replTargetNamespace, name, func(cm *corev1.ConfigMap) bool {
		return cm.Data["setting"] == "pushed-value-2"
	}); err != nil {
		t.Fatalf("Timeout waiting for pushed configmap sync: %v", err)
	}

	// Deleting the source must clean up the pushed ConfigMap (finalizer logic)
	if err := clientset.CoreV1().ConfigMaps(replSourceNamespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("Failed to delete source configmap: %v", err)
	}
	err = wait.PollUntilContextTimeout(ctx, pollInterval, pollTimeout, true, func(ctx context.Context) (bool, error) {
		_, err := clientset.CoreV1().ConfigMaps(replTargetNamespace).Get(ctx, name, metav1.GetOptions{})
		return errors.IsNotFound(err), nil
	})
	if err != nil {
		t.Fatalf("Timeout waiting for pushed configmap cleanup after source deletion: %v", err)
	}

	t.Log("ConfigMap push replication works, including sync and cleanup on source deletion")
}

// TestConfigMapPullReplicationDenied verifies that a ConfigMap without
// consent and with a name not matching the global permission is not
// replicated and a Warning event is created.
func TestConfigMapPullReplicationDenied(t *testing.T) {
	ctx := context.Background()
	ensureReplicationNamespaces(ctx, t)

	// Name does NOT match the global validationPattern "global-*"
	const name = "e2e-cm-denied"
	defer deleteConfigMapIgnoreNotFound(t, replSourceNamespace, name)
	defer deleteConfigMapIgnoreNotFound(t, replTargetNamespace, name)

	source := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: replSourceNamespace,
		},
		Data: map[string]string{"secret-setting": "must-not-leak"},
	}
	if _, err := clientset.CoreV1().ConfigMaps(replSourceNamespace).Create(ctx, source, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Failed to create source configmap: %v", err)
	}

	target := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: replTargetNamespace,
			Annotations: map[string]string{
				AnnotationReplicateFrom: replSourceNamespace + "/" + name,
			},
		},
	}
	if _, err := clientset.CoreV1().ConfigMaps(replTargetNamespace).Create(ctx, target, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Failed to create target configmap: %v", err)
	}

	note, err := waitForWarningEvent(ctx, replTargetNamespace, name, "ConfigMap", "ReplicationFailed")
	if err != nil {
		t.Fatalf("Timeout waiting for ReplicationFailed event: %v", err)
	}
	if !strings.Contains(note, "not allowed") {
		t.Errorf("Expected denial reason in event note, got: %s", note)
	}

	current, err := clientset.CoreV1().ConfigMaps(replTargetNamespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get target configmap: %v", err)
	}
	if len(current.Data) > 0 {
		t.Errorf("Expected empty target configmap, got data: %v", current.Data)
	}

	t.Log("ConfigMap pull replication correctly denied without consent")
}
