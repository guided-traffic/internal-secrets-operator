//go:build integration
// +build integration

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

package integration

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/guided-traffic/internal-secrets-operator/internal/controller"
	"github.com/guided-traffic/internal-secrets-operator/pkg/config"
	"github.com/guided-traffic/internal-secrets-operator/pkg/replicator"
)

// newDirectClient creates a client that talks directly to the API server,
// usable before any manager has been started (e.g. to create namespaces
// whose names are needed in the operator config).
func newDirectClient(t *testing.T) client.Client {
	t.Helper()
	c, err := client.New(restConfig, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		t.Fatalf("failed to create direct client: %v", err)
	}
	return c
}

// setupTestManagerWithConfigMapReplicator creates a manager running the ConfigMapReplicatorReconciler
func setupTestManagerWithConfigMapReplicator(t *testing.T, operatorConfig *config.Config) *testContext {
	t.Helper()

	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme: scheme.Scheme,
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
	})
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	if operatorConfig == nil {
		operatorConfig = config.NewDefaultConfig()
	}

	reconciler := &controller.ConfigMapReplicatorReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		Config:        operatorConfig,
		EventRecorder: mgr.GetEventRecorder("configmap-replicator"),
	}

	counter := atomic.AddInt64(&controllerCounter, 1)
	controllerName := "configmap-replicator-" + time.Now().Format("150405") + "-" + string(rune('a'+counter%26))

	if err := reconciler.SetupWithManagerAndName(mgr, controllerName); err != nil {
		t.Fatalf("failed to setup configmap replicator controller: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := mgr.Start(ctx); err != nil {
			t.Logf("manager stopped: %v", err)
		}
	}()

	// Wait for manager and cache to be ready
	time.Sleep(500 * time.Millisecond)

	return &testContext{
		client: mgr.GetClient(),
		cancel: cancel,
	}
}

// waitForConfigMapReplication waits until the ConfigMap has the expected data
func waitForConfigMapReplication(ctx context.Context, c client.Client, key types.NamespacedName, expectedData map[string]string) (*corev1.ConfigMap, error) {
	var cm corev1.ConfigMap
	deadline := time.Now().Add(replicationTimeout)

	for time.Now().Before(deadline) {
		if err := c.Get(ctx, key, &cm); err != nil {
			time.Sleep(replicationInterval)
			continue
		}

		allPresent := true
		for field, expectedValue := range expectedData {
			if cm.Data[field] != expectedValue {
				allPresent = false
				break
			}
		}
		if allPresent {
			return &cm, nil
		}

		time.Sleep(replicationInterval)
	}

	if err := c.Get(ctx, key, &cm); err != nil {
		return nil, err
	}
	return &cm, nil
}

// TestGlobalPullBasedPermissionSecretReplication verifies that a global
// pull-based permission allows Secret replication without any source-side
// annotation, that targets stay in sync with source changes, and that
// non-matching object names are denied.
func TestGlobalPullBasedPermissionSecretReplication(t *testing.T) {
	directClient := newDirectClient(t)

	sourceNs := createNamespace(t, directClient)
	targetNs := createNamespace(t, directClient)

	cfg := config.NewDefaultConfig()
	cfg.GlobalPullBasedPermissions = []config.GlobalPullBasedPermission{
		{
			FromNamespace:     sourceNs.Name,
			ToNamespace:       targetNs.Name,
			ValidationPattern: "db-*",
			AllowSecret:       true,
		},
	}

	tc := setupTestManagerWithReplicator(t, cfg)
	defer tc.cleanup(t, sourceNs)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = directClient.Delete(ctx, targetNs)
	}()

	ctx := context.Background()

	// Source Secret WITHOUT any replication annotation
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-credentials",
			Namespace: sourceNs.Name,
		},
		Data: map[string][]byte{
			"username": []byte("produser"),
			"password": []byte("prodpass"),
		},
	}
	if err := tc.client.Create(ctx, sourceSecret); err != nil {
		t.Fatalf("failed to create source secret: %v", err)
	}

	targetSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-credentials",
			Namespace: targetNs.Name,
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: sourceNs.Name + "/db-credentials",
			},
		},
	}
	if err := tc.client.Create(ctx, targetSecret); err != nil {
		t.Fatalf("failed to create target secret: %v", err)
	}

	// Replication must happen via global permission
	targetKey := types.NamespacedName{Namespace: targetNs.Name, Name: "db-credentials"}
	replicated, err := waitForSecretReplication(ctx, tc.client, targetKey, map[string]string{
		"username": "produser",
		"password": "prodpass",
	})
	if err != nil {
		t.Fatalf("failed to get replicated secret: %v", err)
	}
	if string(replicated.Data["username"]) != "produser" {
		t.Errorf("replication via global permission did not happen, data: %v", replicated.Data)
	}
	if replicated.Annotations[replicator.AnnotationReplicatedFrom] != sourceNs.Name+"/db-credentials" {
		t.Errorf("missing/wrong replicated-from annotation: %q", replicated.Annotations[replicator.AnnotationReplicatedFrom])
	}

	// Source change must sync to target (watch on annotation-less global sources)
	latestSource := &corev1.Secret{}
	if err := tc.client.Get(ctx, types.NamespacedName{Namespace: sourceNs.Name, Name: "db-credentials"}, latestSource); err != nil {
		t.Fatalf("failed to get source secret: %v", err)
	}
	latestSource.Data["password"] = []byte("rotated-pass")
	if err := tc.client.Update(ctx, latestSource); err != nil {
		t.Fatalf("failed to update source secret: %v", err)
	}

	synced, err := waitForSecretReplication(ctx, tc.client, targetKey, map[string]string{
		"password": "rotated-pass",
	})
	if err != nil {
		t.Fatalf("failed to get synced secret: %v", err)
	}
	if string(synced.Data["password"]) != "rotated-pass" {
		t.Error("target secret was not synced after source change")
	}

	// Secret whose name does not match the validationPattern must NOT be replicated
	deniedSource := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-secret",
			Namespace: sourceNs.Name,
		},
		Data: map[string][]byte{"key": []byte("value")},
	}
	if err := tc.client.Create(ctx, deniedSource); err != nil {
		t.Fatalf("failed to create denied source secret: %v", err)
	}
	deniedTarget := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-secret",
			Namespace: targetNs.Name,
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: sourceNs.Name + "/app-secret",
			},
		},
	}
	if err := tc.client.Create(ctx, deniedTarget); err != nil {
		t.Fatalf("failed to create denied target secret: %v", err)
	}

	time.Sleep(3 * time.Second)

	deniedResult := &corev1.Secret{}
	if err := tc.client.Get(ctx, types.NamespacedName{Namespace: targetNs.Name, Name: "app-secret"}, deniedResult); err != nil {
		t.Fatalf("failed to get denied target secret: %v", err)
	}
	if len(deniedResult.Data) > 0 {
		t.Errorf("secret not matching validationPattern must not be replicated, got data: %v", deniedResult.Data)
	}
}

// TestConfigMapReplicationWithAnnotation verifies pull-based ConfigMap
// replication via the source-side allowlist annotation (mutual consent).
func TestConfigMapReplicationWithAnnotation(t *testing.T) {
	directClient := newDirectClient(t)

	sourceNs := createNamespace(t, directClient)
	targetNs := createNamespace(t, directClient)

	tc := setupTestManagerWithConfigMapReplicator(t, nil)
	defer tc.cleanup(t, sourceNs)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = directClient.Delete(ctx, targetNs)
	}()

	ctx := context.Background()

	sourceCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-config",
			Namespace: sourceNs.Name,
			Annotations: map[string]string{
				replicator.AnnotationReplicatableFromNamespaces: targetNs.Name,
			},
		},
		Data: map[string]string{"setting": "value-1"},
	}
	if err := tc.client.Create(ctx, sourceCM); err != nil {
		t.Fatalf("failed to create source configmap: %v", err)
	}

	targetCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-config",
			Namespace: targetNs.Name,
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: sourceNs.Name + "/app-config",
			},
		},
	}
	if err := tc.client.Create(ctx, targetCM); err != nil {
		t.Fatalf("failed to create target configmap: %v", err)
	}

	targetKey := types.NamespacedName{Namespace: targetNs.Name, Name: "app-config"}
	replicated, err := waitForConfigMapReplication(ctx, tc.client, targetKey, map[string]string{"setting": "value-1"})
	if err != nil {
		t.Fatalf("failed to get replicated configmap: %v", err)
	}
	if replicated.Data["setting"] != "value-1" {
		t.Errorf("configmap replication did not happen, data: %v", replicated.Data)
	}

	// Source change must sync to target
	latestSource := &corev1.ConfigMap{}
	if err := tc.client.Get(ctx, types.NamespacedName{Namespace: sourceNs.Name, Name: "app-config"}, latestSource); err != nil {
		t.Fatalf("failed to get source configmap: %v", err)
	}
	latestSource.Data["setting"] = "value-2"
	if err := tc.client.Update(ctx, latestSource); err != nil {
		t.Fatalf("failed to update source configmap: %v", err)
	}

	synced, err := waitForConfigMapReplication(ctx, tc.client, targetKey, map[string]string{"setting": "value-2"})
	if err != nil {
		t.Fatalf("failed to get synced configmap: %v", err)
	}
	if synced.Data["setting"] != "value-2" {
		t.Error("target configmap was not synced after source change")
	}
}

// TestConfigMapReplicationWithGlobalPermission verifies pull-based ConfigMap
// replication via a global pull-based permission (source has no annotations)
// including binaryData, sync on source change, and denial without consent.
func TestConfigMapReplicationWithGlobalPermission(t *testing.T) {
	directClient := newDirectClient(t)

	sourceNs := createNamespace(t, directClient)
	targetNs := createNamespace(t, directClient)

	cfg := config.NewDefaultConfig()
	cfg.GlobalPullBasedPermissions = []config.GlobalPullBasedPermission{
		{
			FromNamespace:     sourceNs.Name,
			ToNamespace:       targetNs.Name,
			ValidationPattern: "ca-*",
			AllowConfigMap:    true,
		},
	}

	tc := setupTestManagerWithConfigMapReplicator(t, cfg)
	defer tc.cleanup(t, sourceNs)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = directClient.Delete(ctx, targetNs)
	}()

	ctx := context.Background()

	// Source ConfigMap WITHOUT any annotation
	sourceCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-bundle",
			Namespace: sourceNs.Name,
		},
		Data:       map[string]string{"ca.crt": "cert-content"},
		BinaryData: map[string][]byte{"blob": {0xCA, 0xFE}},
	}
	if err := tc.client.Create(ctx, sourceCM); err != nil {
		t.Fatalf("failed to create source configmap: %v", err)
	}

	targetCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-bundle",
			Namespace: targetNs.Name,
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: sourceNs.Name + "/ca-bundle",
			},
		},
	}
	if err := tc.client.Create(ctx, targetCM); err != nil {
		t.Fatalf("failed to create target configmap: %v", err)
	}

	targetKey := types.NamespacedName{Namespace: targetNs.Name, Name: "ca-bundle"}
	replicated, err := waitForConfigMapReplication(ctx, tc.client, targetKey, map[string]string{"ca.crt": "cert-content"})
	if err != nil {
		t.Fatalf("failed to get replicated configmap: %v", err)
	}
	if replicated.Data["ca.crt"] != "cert-content" {
		t.Errorf("configmap replication via global permission did not happen, data: %v", replicated.Data)
	}
	if string(replicated.BinaryData["blob"]) != string([]byte{0xCA, 0xFE}) {
		t.Errorf("binaryData was not replicated, got: %v", replicated.BinaryData)
	}

	// Source change must sync to target (watch on annotation-less global sources)
	latestSource := &corev1.ConfigMap{}
	if err := tc.client.Get(ctx, types.NamespacedName{Namespace: sourceNs.Name, Name: "ca-bundle"}, latestSource); err != nil {
		t.Fatalf("failed to get source configmap: %v", err)
	}
	latestSource.Data["ca.crt"] = "rotated-cert"
	if err := tc.client.Update(ctx, latestSource); err != nil {
		t.Fatalf("failed to update source configmap: %v", err)
	}

	synced, err := waitForConfigMapReplication(ctx, tc.client, targetKey, map[string]string{"ca.crt": "rotated-cert"})
	if err != nil {
		t.Fatalf("failed to get synced configmap: %v", err)
	}
	if synced.Data["ca.crt"] != "rotated-cert" {
		t.Error("target configmap was not synced after source change")
	}

	// ConfigMap not matching the validationPattern must NOT be replicated
	deniedSource := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other-config",
			Namespace: sourceNs.Name,
		},
		Data: map[string]string{"key": "value"},
	}
	if err := tc.client.Create(ctx, deniedSource); err != nil {
		t.Fatalf("failed to create denied source configmap: %v", err)
	}
	deniedTarget := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other-config",
			Namespace: targetNs.Name,
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: sourceNs.Name + "/other-config",
			},
		},
	}
	if err := tc.client.Create(ctx, deniedTarget); err != nil {
		t.Fatalf("failed to create denied target configmap: %v", err)
	}

	time.Sleep(3 * time.Second)

	deniedResult := &corev1.ConfigMap{}
	if err := tc.client.Get(ctx, types.NamespacedName{Namespace: targetNs.Name, Name: "other-config"}, deniedResult); err != nil {
		t.Fatalf("failed to get denied target configmap: %v", err)
	}
	if len(deniedResult.Data) > 0 {
		t.Errorf("configmap not matching validationPattern must not be replicated, got data: %v", deniedResult.Data)
	}
	if deniedResult.Annotations[replicator.AnnotationReplicatedFrom] != "" {
		t.Error("denied configmap must not have replicated-from annotation")
	}
}
