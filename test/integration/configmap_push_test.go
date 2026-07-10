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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/guided-traffic/internal-secrets-operator/pkg/replicator"
)

// TestConfigMapPushReplication verifies push-based ConfigMap replication:
// create in target namespaces, sync on source change, skip unowned targets,
// and cleanup of pushed ConfigMaps when the source is deleted.
func TestConfigMapPushReplication(t *testing.T) {
	directClient := newDirectClient(t)

	sourceNs := createNamespace(t, directClient)
	targetNs := createNamespace(t, directClient)
	blockedNs := createNamespace(t, directClient)

	tc := setupTestManagerWithConfigMapReplicator(t, nil)
	defer tc.cleanup(t, sourceNs)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = directClient.Delete(ctx, targetNs)
		_ = directClient.Delete(ctx, blockedNs)
	}()

	ctx := context.Background()

	// Pre-existing unowned ConfigMap in blockedNs - push must skip it
	blocking := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pushed-config",
			Namespace: blockedNs.Name,
		},
		Data: map[string]string{"setting": "pre-existing"},
	}
	if err := tc.client.Create(ctx, blocking); err != nil {
		t.Fatalf("failed to create blocking configmap: %v", err)
	}

	// Source ConfigMap pushing to both namespaces
	source := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pushed-config",
			Namespace: sourceNs.Name,
			Annotations: map[string]string{
				replicator.AnnotationReplicateTo: targetNs.Name + "," + blockedNs.Name,
			},
		},
		Data:       map[string]string{"setting": "value-1"},
		BinaryData: map[string][]byte{"blob": {0x0B}},
	}
	if err := tc.client.Create(ctx, source); err != nil {
		t.Fatalf("failed to create source configmap: %v", err)
	}

	// Pushed ConfigMap must appear in target namespace
	targetKey := types.NamespacedName{Namespace: targetNs.Name, Name: "pushed-config"}
	pushed, err := waitForConfigMapReplication(ctx, tc.client, targetKey, map[string]string{"setting": "value-1"})
	if err != nil {
		t.Fatalf("failed to get pushed configmap: %v", err)
	}
	if pushed.Annotations[replicator.AnnotationReplicatedFrom] != sourceNs.Name+"/pushed-config" {
		t.Errorf("replicated-from = %q", pushed.Annotations[replicator.AnnotationReplicatedFrom])
	}
	if string(pushed.BinaryData["blob"]) != string([]byte{0x0B}) {
		t.Errorf("binaryData not pushed, got %v", pushed.BinaryData)
	}

	// Source must have the cleanup finalizer
	latestSource := &corev1.ConfigMap{}
	if err := tc.client.Get(ctx, types.NamespacedName{Namespace: sourceNs.Name, Name: "pushed-config"}, latestSource); err != nil {
		t.Fatalf("failed to get source configmap: %v", err)
	}
	if !replicator.HasFinalizer(latestSource) {
		t.Error("expected cleanup finalizer on source configmap")
	}

	// Unowned ConfigMap in blockedNs must stay untouched
	time.Sleep(2 * time.Second)
	blockedResult := &corev1.ConfigMap{}
	if err := tc.client.Get(ctx, types.NamespacedName{Namespace: blockedNs.Name, Name: "pushed-config"}, blockedResult); err != nil {
		t.Fatalf("failed to get blocking configmap: %v", err)
	}
	if blockedResult.Data["setting"] != "pre-existing" {
		t.Error("unowned configmap was modified by push replication")
	}

	// Source change must sync to pushed target
	latestSource.Data["setting"] = "value-2"
	if err := tc.client.Update(ctx, latestSource); err != nil {
		t.Fatalf("failed to update source configmap: %v", err)
	}
	if _, err := waitForConfigMapReplication(ctx, tc.client, targetKey, map[string]string{"setting": "value-2"}); err != nil {
		t.Fatalf("pushed configmap was not synced: %v", err)
	}

	// Deleting the source must clean up the pushed ConfigMap (finalizer logic)
	if err := tc.client.Delete(ctx, latestSource); err != nil {
		t.Fatalf("failed to delete source configmap: %v", err)
	}

	deadline := time.Now().Add(replicationTimeout)
	for time.Now().Before(deadline) {
		err := tc.client.Get(ctx, targetKey, &corev1.ConfigMap{})
		if apierrors.IsNotFound(err) {
			break
		}
		time.Sleep(replicationInterval)
	}
	if err := tc.client.Get(ctx, targetKey, &corev1.ConfigMap{}); !apierrors.IsNotFound(err) {
		t.Errorf("pushed configmap was not cleaned up after source deletion, get error: %v", err)
	}

	// The unowned ConfigMap must survive the cleanup
	if err := tc.client.Get(ctx, types.NamespacedName{Namespace: blockedNs.Name, Name: "pushed-config"}, blockedResult); err != nil {
		t.Errorf("unowned configmap must not be deleted by cleanup: %v", err)
	}
}
