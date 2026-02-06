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
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/guided-traffic/internal-secrets-operator/pkg/config"
	"github.com/guided-traffic/internal-secrets-operator/pkg/replicator"
)

const (
	// Test timeouts for replication tests
	replicationTimeout  = 30 * time.Second
	replicationInterval = 250 * time.Millisecond
)

// waitForSecretReplication waits for a secret to have specific data replicated
func waitForSecretReplication(ctx context.Context, c client.Client, key types.NamespacedName, expectedData map[string]string) (*corev1.Secret, error) {
	var secret corev1.Secret
	deadline := time.Now().Add(replicationTimeout)

	for time.Now().Before(deadline) {
		if err := c.Get(ctx, key, &secret); err != nil {
			time.Sleep(replicationInterval)
			continue
		}

		// Check if all expected data is present
		allPresent := true
		for field, expectedValue := range expectedData {
			actualValue, ok := secret.Data[field]
			if !ok || string(actualValue) != expectedValue {
				allPresent = false
				break
			}
		}

		if allPresent {
			return &secret, nil
		}

		time.Sleep(replicationInterval)
	}

	// Return whatever we have
	if err := c.Get(ctx, key, &secret); err != nil {
		return nil, err
	}
	return &secret, nil
}

// waitForSecretDeletion waits for a secret to be deleted
func waitForSecretDeletion(ctx context.Context, c client.Client, key types.NamespacedName) error {
	deadline := time.Now().Add(replicationTimeout)

	for time.Now().Before(deadline) {
		secret := &corev1.Secret{}
		err := c.Get(ctx, key, secret)
		if apierrors.IsNotFound(err) {
			return nil
		}
		time.Sleep(replicationInterval)
	}

	return fmt.Errorf("secret still exists after timeout")
}

// consistentlySecretEmpty checks that a secret remains empty for a duration
func consistentlySecretEmpty(ctx context.Context, c client.Client, key types.NamespacedName, duration time.Duration) bool {
	deadline := time.Now().Add(duration)

	for time.Now().Before(deadline) {
		secret := &corev1.Secret{}
		err := c.Get(ctx, key, secret)
		// Ignore NotFound errors (secret doesn't exist yet or was deleted)
		if err != nil && !apierrors.IsNotFound(err) {
			return false
		}
		// If secret exists and has data, it's not empty
		if err == nil && len(secret.Data) > 0 {
			return false
		}
		time.Sleep(replicationInterval)
	}

	return true
}

// waitForSecretUpdate waits for a secret to have a specific field value
func waitForSecretUpdate(ctx context.Context, c client.Client, key types.NamespacedName, field string, expectedValue string) (*corev1.Secret, error) {
	var secret corev1.Secret
	deadline := time.Now().Add(replicationTimeout)

	for time.Now().Before(deadline) {
		if err := c.Get(ctx, key, &secret); err != nil {
			time.Sleep(replicationInterval)
			continue
		}

		actualValue, ok := secret.Data[field]
		if ok && string(actualValue) == expectedValue {
			return &secret, nil
		}

		time.Sleep(replicationInterval)
	}

	// Return whatever we have
	if err := c.Get(ctx, key, &secret); err != nil {
		return nil, err
	}
	return &secret, fmt.Errorf("timeout waiting for secret update: expected %s=%s", field, expectedValue)
}

func TestSecretReplication(t *testing.T) {
	// Setup test manager with replication enabled
	cfg := config.NewDefaultConfig()
	cfg.Features.SecretReplicator = true
	tc := setupTestManagerWithReplicator(t, cfg)
	defer tc.cancel()

	ctx := context.Background()

	t.Run("PullBasedReplication_MutualConsent", func(t *testing.T) {
		// Create source namespace
		sourceNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "repl-source-",
			},
		}
		if err := tc.client.Create(ctx, sourceNS); err != nil {
			t.Fatalf("failed to create source namespace: %v", err)
		}
		defer tc.client.Delete(ctx, sourceNS)

		// Create target namespace
		targetNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "repl-target-",
			},
		}
		if err := tc.client.Create(ctx, targetNS); err != nil {
			t.Fatalf("failed to create target namespace: %v", err)
		}
		defer tc.client.Delete(ctx, targetNS)

		// Create source Secret with allowlist
		sourceSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pull-test-secret",
				Namespace: sourceNS.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicatableFromNamespaces: targetNS.Name,
				},
			},
			Data: map[string][]byte{
				"username": []byte("testuser"),
				"password": []byte("testpass"),
			},
		}
		if err := tc.client.Create(ctx, sourceSecret); err != nil {
			t.Fatalf("failed to create source secret: %v", err)
		}
		defer tc.client.Delete(ctx, sourceSecret)

		// Create target Secret with replicate-from
		targetSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pull-test-secret",
				Namespace: targetNS.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicateFrom: sourceNS.Name + "/pull-test-secret",
				},
			},
		}
		if err := tc.client.Create(ctx, targetSecret); err != nil {
			t.Fatalf("failed to create target secret: %v", err)
		}
		defer tc.client.Delete(ctx, targetSecret)

		// Wait for replication to occur
		expectedData := map[string]string{
			"username": "testuser",
			"password": "testpass",
		}
		replicatedSecret, err := waitForSecretReplication(ctx, tc.client, types.NamespacedName{
			Namespace: targetNS.Name,
			Name:      "pull-test-secret",
		}, expectedData)

		if err != nil {
			t.Fatalf("failed to wait for replication: %v", err)
		}

		// Verify replicated-from annotation
		if replicatedSecret.Annotations[replicator.AnnotationReplicatedFrom] != sourceNS.Name+"/pull-test-secret" {
			t.Errorf("expected replicated-from annotation, got %v", replicatedSecret.Annotations[replicator.AnnotationReplicatedFrom])
		}
	})

	t.Run("PullBasedReplication_SourceUpdateSync_Q5", func(t *testing.T) {
		// Test Q5: Target Secrets stay synchronized with their sources

		// Create namespaces
		sourceNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "sync-source-",
			},
		}
		if err := tc.client.Create(ctx, sourceNS); err != nil {
			t.Fatalf("failed to create source namespace: %v", err)
		}
		defer tc.client.Delete(ctx, sourceNS)

		targetNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "sync-target-",
			},
		}
		if err := tc.client.Create(ctx, targetNS); err != nil {
			t.Fatalf("failed to create target namespace: %v", err)
		}
		defer tc.client.Delete(ctx, targetNS)

		// Create source Secret
		sourceSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "sync-secret",
				Namespace: sourceNS.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicatableFromNamespaces: targetNS.Name,
				},
			},
			Data: map[string][]byte{
				"version": []byte("v1"),
			},
		}
		if err := tc.client.Create(ctx, sourceSecret); err != nil {
			t.Fatalf("failed to create source secret: %v", err)
		}
		defer tc.client.Delete(ctx, sourceSecret)

		// Create target Secret
		targetSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "sync-secret",
				Namespace: targetNS.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicateFrom: sourceNS.Name + "/sync-secret",
				},
			},
		}
		if err := tc.client.Create(ctx, targetSecret); err != nil {
			t.Fatalf("failed to create target secret: %v", err)
		}
		defer tc.client.Delete(ctx, targetSecret)

		// Wait for initial replication
		_, err := waitForSecretReplication(ctx, tc.client, types.NamespacedName{
			Namespace: targetNS.Name,
			Name:      "sync-secret",
		}, map[string]string{"version": "v1"})
		if err != nil {
			t.Fatalf("initial replication failed: %v", err)
		}

		// Update source Secret
		if err := tc.client.Get(ctx, types.NamespacedName{
			Namespace: sourceNS.Name,
			Name:      "sync-secret",
		}, sourceSecret); err != nil {
			t.Fatalf("failed to get source secret: %v", err)
		}

		sourceSecret.Data["version"] = []byte("v2")
		if err := tc.client.Update(ctx, sourceSecret); err != nil {
			t.Fatalf("failed to update source secret: %v", err)
		}

		// Wait for update to propagate to target (automatic sync)
		// The controller watches source Secrets with replicatable-from-namespaces
		// and triggers reconciliation of targets when the source changes.
		updatedTarget, err := waitForSecretUpdate(ctx, tc.client, types.NamespacedName{
			Namespace: targetNS.Name,
			Name:      "sync-secret",
		}, "version", "v2")
		if err != nil {
			t.Fatalf("source update did not propagate to target: %v", err)
		}

		if string(updatedTarget.Data["version"]) != "v2" {
			t.Errorf("expected version v2 in target, got %s", string(updatedTarget.Data["version"]))
		}
	})

	t.Run("PullBasedReplication_SourceDeletionSnapshot_Q6", func(t *testing.T) {
		// Test Q6: When source is deleted, target keeps last known data (snapshot behavior)

		// Create namespaces
		sourceNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "snapshot-source-",
			},
		}
		if err := tc.client.Create(ctx, sourceNS); err != nil {
			t.Fatalf("failed to create source namespace: %v", err)
		}
		defer tc.client.Delete(ctx, sourceNS)

		targetNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "snapshot-target-",
			},
		}
		if err := tc.client.Create(ctx, targetNS); err != nil {
			t.Fatalf("failed to create target namespace: %v", err)
		}
		defer tc.client.Delete(ctx, targetNS)

		// Create source Secret
		sourceSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "snapshot-secret",
				Namespace: sourceNS.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicatableFromNamespaces: targetNS.Name,
				},
			},
			Data: map[string][]byte{
				"key": []byte("snapshot-value"),
			},
		}
		if err := tc.client.Create(ctx, sourceSecret); err != nil {
			t.Fatalf("failed to create source secret: %v", err)
		}

		// Create target Secret
		targetSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "snapshot-secret",
				Namespace: targetNS.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicateFrom: sourceNS.Name + "/snapshot-secret",
				},
			},
		}
		if err := tc.client.Create(ctx, targetSecret); err != nil {
			t.Fatalf("failed to create target secret: %v", err)
		}
		defer tc.client.Delete(ctx, targetSecret)

		// Wait for initial replication
		_, err := waitForSecretReplication(ctx, tc.client, types.NamespacedName{
			Namespace: targetNS.Name,
			Name:      "snapshot-secret",
		}, map[string]string{"key": "snapshot-value"})
		if err != nil {
			t.Fatalf("initial replication failed: %v", err)
		}

		// Delete source Secret
		if err := tc.client.Delete(ctx, sourceSecret); err != nil {
			t.Fatalf("failed to delete source secret: %v", err)
		}

		// Wait a bit for any potential cleanup
		time.Sleep(2 * time.Second)

		// Verify target Secret still exists with snapshot data
		var snapshotSecret corev1.Secret
		if err := tc.client.Get(ctx, types.NamespacedName{
			Namespace: targetNS.Name,
			Name:      "snapshot-secret",
		}, &snapshotSecret); err != nil {
			t.Fatalf("target secret should still exist (snapshot behavior): %v", err)
		}

		// Verify data is preserved
		if string(snapshotSecret.Data["key"]) != "snapshot-value" {
			t.Errorf("expected snapshot data to be preserved, got %s", string(snapshotSecret.Data["key"]))
		}
	})

	t.Run("PullBasedReplication_DenyUnauthorized", func(t *testing.T) {
		// Create namespaces
		sourceNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "deny-source-",
			},
		}
		if err := tc.client.Create(ctx, sourceNS); err != nil {
			t.Fatalf("failed to create source namespace: %v", err)
		}
		defer tc.client.Delete(ctx, sourceNS)

		unauthorizedNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "unauthorized-",
			},
		}
		if err := tc.client.Create(ctx, unauthorizedNS); err != nil {
			t.Fatalf("failed to create unauthorized namespace: %v", err)
		}
		defer tc.client.Delete(ctx, unauthorizedNS)

		// Create source Secret with limited allowlist
		sourceSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "denied-secret",
				Namespace: sourceNS.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicatableFromNamespaces: "other-namespace",
				},
			},
			Data: map[string][]byte{
				"secret": []byte("data"),
			},
		}
		if err := tc.client.Create(ctx, sourceSecret); err != nil {
			t.Fatalf("failed to create source secret: %v", err)
		}
		defer tc.client.Delete(ctx, sourceSecret)

		// Create target Secret trying to replicate
		targetSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "denied-secret",
				Namespace: unauthorizedNS.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicateFrom: sourceNS.Name + "/denied-secret",
				},
			},
		}
		if err := tc.client.Create(ctx, targetSecret); err != nil {
			t.Fatalf("failed to create target secret: %v", err)
		}
		defer tc.client.Delete(ctx, targetSecret)

		// Wait a bit and verify data was NOT replicated
		if !consistentlySecretEmpty(ctx, tc.client, types.NamespacedName{
			Namespace: unauthorizedNS.Name,
			Name:      "denied-secret",
		}, 5*time.Second) {
			t.Error("expected secret to remain empty (replication should be denied)")
		}
	})

	t.Run("PullBasedReplication_WildcardPatterns", func(t *testing.T) {
		// Create source namespace with unique prefix
		sourceNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "wildcard-source-",
			},
		}
		if err := tc.client.Create(ctx, sourceNS); err != nil {
			t.Fatalf("failed to create source namespace: %v", err)
		}
		defer tc.client.Delete(ctx, sourceNS)

		// Create target namespaces with env- prefix to match wildcard
		target1NS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "env-staging-",
			},
		}
		if err := tc.client.Create(ctx, target1NS); err != nil {
			t.Fatalf("failed to create target1 namespace: %v", err)
		}
		defer tc.client.Delete(ctx, target1NS)

		target2NS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "env-dev-",
			},
		}
		if err := tc.client.Create(ctx, target2NS); err != nil {
			t.Fatalf("failed to create target2 namespace: %v", err)
		}
		defer tc.client.Delete(ctx, target2NS)

		// Create source Secret with wildcard allowlist pattern
		sourceSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "wildcard-secret",
				Namespace: sourceNS.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicatableFromNamespaces: "env-*",
				},
			},
			Data: map[string][]byte{
				"data": []byte("wildcard-test"),
			},
		}
		if err := tc.client.Create(ctx, sourceSecret); err != nil {
			t.Fatalf("failed to create source secret: %v", err)
		}
		defer tc.client.Delete(ctx, sourceSecret)

		// Create target Secrets in both namespaces
		target1Secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "wildcard-secret",
				Namespace: target1NS.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicateFrom: sourceNS.Name + "/wildcard-secret",
				},
			},
		}
		if err := tc.client.Create(ctx, target1Secret); err != nil {
			t.Fatalf("failed to create target1 secret: %v", err)
		}
		defer tc.client.Delete(ctx, target1Secret)

		target2Secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "wildcard-secret",
				Namespace: target2NS.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicateFrom: sourceNS.Name + "/wildcard-secret",
				},
			},
		}
		if err := tc.client.Create(ctx, target2Secret); err != nil {
			t.Fatalf("failed to create target2 secret: %v", err)
		}
		defer tc.client.Delete(ctx, target2Secret)

		// Wait for both secrets to be replicated
		expectedData := map[string]string{
			"data": "wildcard-test",
		}

		_, err := waitForSecretReplication(ctx, tc.client, types.NamespacedName{
			Namespace: target1NS.Name,
			Name:      "wildcard-secret",
		}, expectedData)
		if err != nil {
			t.Errorf("target1 secret was not replicated: %v", err)
		}

		_, err = waitForSecretReplication(ctx, tc.client, types.NamespacedName{
			Namespace: target2NS.Name,
			Name:      "wildcard-secret",
		}, expectedData)
		if err != nil {
			t.Errorf("target2 secret was not replicated: %v", err)
		}
	})

	t.Run("PushBasedReplication_Basic", func(t *testing.T) {
		// Create namespaces
		sourceNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "push-source-",
			},
		}
		if err := tc.client.Create(ctx, sourceNS); err != nil {
			t.Fatalf("failed to create source namespace: %v", err)
		}
		defer tc.client.Delete(ctx, sourceNS)

		targetNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "push-target-",
			},
		}
		if err := tc.client.Create(ctx, targetNS); err != nil {
			t.Fatalf("failed to create target namespace: %v", err)
		}
		defer tc.client.Delete(ctx, targetNS)

		// Create source Secret with replicate-to annotation
		sourceSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "push-secret",
				Namespace: sourceNS.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicateTo: targetNS.Name,
				},
			},
			Data: map[string][]byte{
				"key": []byte("pushed-value"),
			},
		}
		if err := tc.client.Create(ctx, sourceSecret); err != nil {
			t.Fatalf("failed to create source secret: %v", err)
		}
		defer tc.client.Delete(ctx, sourceSecret)

		// Wait for Secret to be created in target namespace
		expectedData := map[string]string{
			"key": "pushed-value",
		}
		pushedSecret, err := waitForSecretReplication(ctx, tc.client, types.NamespacedName{
			Namespace: targetNS.Name,
			Name:      "push-secret",
		}, expectedData)

		if err != nil {
			t.Fatalf("pushed secret was not created: %v", err)
		}

		// Verify replicated-from annotation
		if pushedSecret.Annotations[replicator.AnnotationReplicatedFrom] != sourceNS.Name+"/push-secret" {
			t.Errorf("expected replicated-from annotation, got %v", pushedSecret.Annotations[replicator.AnnotationReplicatedFrom])
		}

		// Cleanup pushed secret
		defer tc.client.Delete(ctx, pushedSecret)
	})

	t.Run("PushBasedReplication_UpdatePropagation", func(t *testing.T) {
		// Create namespaces
		sourceNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "update-source-",
			},
		}
		if err := tc.client.Create(ctx, sourceNS); err != nil {
			t.Fatalf("failed to create source namespace: %v", err)
		}
		defer tc.client.Delete(ctx, sourceNS)

		targetNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "update-target-",
			},
		}
		if err := tc.client.Create(ctx, targetNS); err != nil {
			t.Fatalf("failed to create target namespace: %v", err)
		}
		defer tc.client.Delete(ctx, targetNS)

		// Create source Secret
		sourceSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "update-secret",
				Namespace: sourceNS.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicateTo: targetNS.Name,
				},
			},
			Data: map[string][]byte{
				"version": []byte("v1"),
			},
		}
		if err := tc.client.Create(ctx, sourceSecret); err != nil {
			t.Fatalf("failed to create source secret: %v", err)
		}
		defer tc.client.Delete(ctx, sourceSecret)

		// Wait for initial push
		_, err := waitForSecretReplication(ctx, tc.client, types.NamespacedName{
			Namespace: targetNS.Name,
			Name:      "update-secret",
		}, map[string]string{"version": "v1"})
		if err != nil {
			t.Fatalf("initial push failed: %v", err)
		}

		// Update source Secret
		if err := tc.client.Get(ctx, types.NamespacedName{
			Namespace: sourceNS.Name,
			Name:      "update-secret",
		}, sourceSecret); err != nil {
			t.Fatalf("failed to get source secret: %v", err)
		}

		sourceSecret.Data["version"] = []byte("v2")
		if err := tc.client.Update(ctx, sourceSecret); err != nil {
			t.Fatalf("failed to update source secret: %v", err)
		}

		// Wait for update to propagate
		updatedSecret, err := waitForSecretReplication(ctx, tc.client, types.NamespacedName{
			Namespace: targetNS.Name,
			Name:      "update-secret",
		}, map[string]string{"version": "v2"})
		if err != nil {
			t.Fatalf("update did not propagate: %v", err)
		}

		if string(updatedSecret.Data["version"]) != "v2" {
			t.Errorf("expected version v2, got %s", string(updatedSecret.Data["version"]))
		}

		// Cleanup
		defer tc.client.Delete(ctx, updatedSecret)
	})

	t.Run("PushBasedReplication_CleanupOnDeletion", func(t *testing.T) {
		// Create namespaces
		sourceNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "cleanup-source-",
			},
		}
		if err := tc.client.Create(ctx, sourceNS); err != nil {
			t.Fatalf("failed to create source namespace: %v", err)
		}
		defer tc.client.Delete(ctx, sourceNS)

		targetNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "cleanup-target-",
			},
		}
		if err := tc.client.Create(ctx, targetNS); err != nil {
			t.Fatalf("failed to create target namespace: %v", err)
		}
		defer tc.client.Delete(ctx, targetNS)

		// Create source Secret
		sourceSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cleanup-secret",
				Namespace: sourceNS.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicateTo: targetNS.Name,
				},
			},
			Data: map[string][]byte{
				"data": []byte("test"),
			},
		}
		if err := tc.client.Create(ctx, sourceSecret); err != nil {
			t.Fatalf("failed to create source secret: %v", err)
		}

		// Wait for push
		_, err := waitForSecretReplication(ctx, tc.client, types.NamespacedName{
			Namespace: targetNS.Name,
			Name:      "cleanup-secret",
		}, map[string]string{"data": "test"})
		if err != nil {
			t.Fatalf("push failed: %v", err)
		}

		// Delete source Secret
		if err := tc.client.Delete(ctx, sourceSecret); err != nil {
			t.Fatalf("failed to delete source secret: %v", err)
		}

		// Wait for pushed Secret to be deleted
		if err := waitForSecretDeletion(ctx, tc.client, types.NamespacedName{
			Namespace: targetNS.Name,
			Name:      "cleanup-secret",
		}); err != nil {
			t.Errorf("pushed secret was not cleaned up: %v", err)
		}
	})
}

// TestFeatureInteractions tests the interaction between secret generation and replication features
func TestFeatureInteractions(t *testing.T) {
	// Setup test manager with both controllers
	cfg := config.NewDefaultConfig()
	cfg.Features.SecretGenerator = true
	cfg.Features.SecretReplicator = true

	// We need to setup both controllers for these tests
	// For now, we'll create separate test contexts for simplicity
	tcReplicator := setupTestManagerWithReplicator(t, cfg)
	defer tcReplicator.cancel()

	// Small delay to ensure controllers are ready
	time.Sleep(500 * time.Millisecond)

	ctx := context.Background()

	t.Run("RejectConflictingAnnotations", func(t *testing.T) {
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "conflict-test-",
			},
		}
		if err := tcReplicator.client.Create(ctx, ns); err != nil {
			t.Fatalf("failed to create namespace: %v", err)
		}
		defer tcReplicator.client.Delete(ctx, ns)

		// Create Secret with conflicting annotations
		conflictSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "conflict-secret",
				Namespace: ns.Name,
				Annotations: map[string]string{
					"iso.gtrfc.com/autogenerate":       "password",
					replicator.AnnotationReplicateFrom: "other-ns/other-secret",
				},
			},
		}
		if err := tcReplicator.client.Create(ctx, conflictSecret); err != nil {
			t.Fatalf("failed to create conflict secret: %v", err)
		}
		defer tcReplicator.client.Delete(ctx, conflictSecret)

		// Secret should remain unchanged (no data generated or replicated)
		if !consistentlySecretEmpty(ctx, tcReplicator.client, types.NamespacedName{
			Namespace: ns.Name,
			Name:      "conflict-secret",
		}, 5*time.Second) {
			t.Error("expected secret to remain empty due to conflicting annotations")
		}
	})

	t.Run("AllowAutogenerateWithReplicatable", func(t *testing.T) {
		// This test requires the SecretReconciler to be active as well
		// For now, we'll test that the annotations don't conflict
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "combined-test-",
			},
		}
		if err := tcReplicator.client.Create(ctx, ns); err != nil {
			t.Fatalf("failed to create namespace: %v", err)
		}
		defer tcReplicator.client.Delete(ctx, ns)

		// Create Secret with both autogenerate and replicatable-from-namespaces
		combinedSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "combined-secret",
				Namespace: ns.Name,
				Annotations: map[string]string{
					"iso.gtrfc.com/autogenerate":                    "password",
					replicator.AnnotationReplicatableFromNamespaces: "*",
				},
			},
		}
		if err := tcReplicator.client.Create(ctx, combinedSecret); err != nil {
			t.Fatalf("failed to create combined secret: %v", err)
		}
		defer tcReplicator.client.Delete(ctx, combinedSecret)

		// The replicator should not interfere with this Secret
		// (autogenerate is handled by the generator controller, which is not active in this test)
		// We just verify that the replicator doesn't touch it
		time.Sleep(2 * time.Second)

		// Fetch the secret and verify replicatable annotation is still there
		var secret corev1.Secret
		if err := tcReplicator.client.Get(ctx, types.NamespacedName{
			Namespace: ns.Name,
			Name:      "combined-secret",
		}, &secret); err != nil {
			t.Fatalf("failed to get secret: %v", err)
		}

		if secret.Annotations[replicator.AnnotationReplicatableFromNamespaces] != "*" {
			t.Errorf("expected replicatable-from-namespaces annotation to be preserved")
		}
	})
}

// TestCharacterClassPatternsIntegration tests glob patterns with character classes in integration
func TestCharacterClassPatternsIntegration(t *testing.T) {
	cfg := config.NewDefaultConfig()
	cfg.Features.SecretReplicator = true
	tc := setupTestManagerWithReplicator(t, cfg)
	defer tc.cancel()

	ctx := context.Background()

	t.Run("CharacterRange_0_9", func(t *testing.T) {
		// Test pattern with [0-9] character range

		sourceNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "char-source-",
			},
		}
		if err := tc.client.Create(ctx, sourceNS); err != nil {
			t.Fatalf("failed to create source namespace: %v", err)
		}
		defer tc.client.Delete(ctx, sourceNS)

		// Create target namespace with digit suffix
		targetNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "env-5" + fmt.Sprintf("-%d", time.Now().UnixNano()%1000), // Make unique
			},
		}
		if err := tc.client.Create(ctx, targetNS); err != nil {
			t.Fatalf("failed to create target namespace: %v", err)
		}
		defer tc.client.Delete(ctx, targetNS)

		// Create source Secret with [0-9] pattern - only matches single digit
		sourceSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "char-range-secret",
				Namespace: sourceNS.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicatableFromNamespaces: "env-[0-9]*", // matches env-5-xxx
				},
			},
			Data: map[string][]byte{
				"data": []byte("char-range-test"),
			},
		}
		if err := tc.client.Create(ctx, sourceSecret); err != nil {
			t.Fatalf("failed to create source secret: %v", err)
		}
		defer tc.client.Delete(ctx, sourceSecret)

		// Create target Secret
		targetSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "char-range-secret",
				Namespace: targetNS.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicateFrom: sourceNS.Name + "/char-range-secret",
				},
			},
		}
		if err := tc.client.Create(ctx, targetSecret); err != nil {
			t.Fatalf("failed to create target secret: %v", err)
		}
		defer tc.client.Delete(ctx, targetSecret)

		// Wait for replication
		_, err := waitForSecretReplication(ctx, tc.client, types.NamespacedName{
			Namespace: targetNS.Name,
			Name:      "char-range-secret",
		}, map[string]string{"data": "char-range-test"})
		if err != nil {
			t.Errorf("character range pattern [0-9] did not match: %v", err)
		}
	})

	t.Run("PushBasedReplication_SkipUnownedTarget_Q18", func(t *testing.T) {
		// Test Q18: Skip if target exists but not owned by us

		sourceNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "skip-source-",
			},
		}
		if err := tc.client.Create(ctx, sourceNS); err != nil {
			t.Fatalf("failed to create source namespace: %v", err)
		}
		defer tc.client.Delete(ctx, sourceNS)

		targetNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "skip-target-",
			},
		}
		if err := tc.client.Create(ctx, targetNS); err != nil {
			t.Fatalf("failed to create target namespace: %v", err)
		}
		defer tc.client.Delete(ctx, targetNS)

		// Create existing unowned target Secret FIRST
		existingTarget := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "existing-secret",
				Namespace: targetNS.Name,
				// No replicated-from annotation - not owned by us
			},
			Data: map[string][]byte{
				"original": []byte("original-value"),
			},
		}
		if err := tc.client.Create(ctx, existingTarget); err != nil {
			t.Fatalf("failed to create existing target secret: %v", err)
		}
		defer tc.client.Delete(ctx, existingTarget)

		// Create source Secret with replicate-to
		sourceSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "existing-secret",
				Namespace: sourceNS.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicateTo: targetNS.Name,
				},
			},
			Data: map[string][]byte{
				"key": []byte("should-not-overwrite"),
			},
		}
		if err := tc.client.Create(ctx, sourceSecret); err != nil {
			t.Fatalf("failed to create source secret: %v", err)
		}
		defer tc.client.Delete(ctx, sourceSecret)

		// Wait and verify target was NOT modified
		time.Sleep(3 * time.Second)

		var unmodifiedTarget corev1.Secret
		if err := tc.client.Get(ctx, types.NamespacedName{
			Namespace: targetNS.Name,
			Name:      "existing-secret",
		}, &unmodifiedTarget); err != nil {
			t.Fatalf("failed to get target secret: %v", err)
		}

		// Should still have original data
		if string(unmodifiedTarget.Data["original"]) != "original-value" {
			t.Error("unowned target secret was modified")
		}

		// Should NOT have replicated-from annotation
		if unmodifiedTarget.Annotations[replicator.AnnotationReplicatedFrom] != "" {
			t.Error("unowned target secret should not have replicated-from annotation")
		}
	})

	t.Run("OneSourceToMultipleTargets_Q7", func(t *testing.T) {
		// Test Q7: One source can replicate to multiple targets

		sourceNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "multi-source-",
			},
		}
		if err := tc.client.Create(ctx, sourceNS); err != nil {
			t.Fatalf("failed to create source namespace: %v", err)
		}
		defer tc.client.Delete(ctx, sourceNS)

		// Create multiple target namespaces
		targetNS1 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "multi-target1-",
			},
		}
		if err := tc.client.Create(ctx, targetNS1); err != nil {
			t.Fatalf("failed to create target1 namespace: %v", err)
		}
		defer tc.client.Delete(ctx, targetNS1)

		targetNS2 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "multi-target2-",
			},
		}
		if err := tc.client.Create(ctx, targetNS2); err != nil {
			t.Fatalf("failed to create target2 namespace: %v", err)
		}
		defer tc.client.Delete(ctx, targetNS2)

		// Create source Secret with wildcard allowlist
		sourceSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "multi-source-secret",
				Namespace: sourceNS.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicatableFromNamespaces: "multi-target*",
				},
			},
			Data: map[string][]byte{
				"shared": []byte("shared-data"),
			},
		}
		if err := tc.client.Create(ctx, sourceSecret); err != nil {
			t.Fatalf("failed to create source secret: %v", err)
		}
		defer tc.client.Delete(ctx, sourceSecret)

		// Create target Secrets in both namespaces
		target1 := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "multi-source-secret",
				Namespace: targetNS1.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicateFrom: sourceNS.Name + "/multi-source-secret",
				},
			},
		}
		if err := tc.client.Create(ctx, target1); err != nil {
			t.Fatalf("failed to create target1 secret: %v", err)
		}
		defer tc.client.Delete(ctx, target1)

		target2 := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "multi-source-secret",
				Namespace: targetNS2.Name,
				Annotations: map[string]string{
					replicator.AnnotationReplicateFrom: sourceNS.Name + "/multi-source-secret",
				},
			},
		}
		if err := tc.client.Create(ctx, target2); err != nil {
			t.Fatalf("failed to create target2 secret: %v", err)
		}
		defer tc.client.Delete(ctx, target2)

		// Wait for both to be replicated
		expectedData := map[string]string{"shared": "shared-data"}

		_, err := waitForSecretReplication(ctx, tc.client, types.NamespacedName{
			Namespace: targetNS1.Name,
			Name:      "multi-source-secret",
		}, expectedData)
		if err != nil {
			t.Errorf("target1 was not replicated: %v", err)
		}

		_, err = waitForSecretReplication(ctx, tc.client, types.NamespacedName{
			Namespace: targetNS2.Name,
			Name:      "multi-source-secret",
		}, expectedData)
		if err != nil {
			t.Errorf("target2 was not replicated: %v", err)
		}
	})
}

// TestPushReplication_RetryAfterConflictingSecretDeleted tests that when a conflicting
// (unowned) target Secret is deleted, the controller automatically retries push replication
// and creates the replicated Secret without requiring a controller restart.
func TestPushReplication_RetryAfterConflictingSecretDeleted(t *testing.T) {
	cfg := config.NewDefaultConfig()
	cfg.Features.SecretReplicator = true
	tc := setupTestManagerWithReplicator(t, cfg)
	defer tc.cancel()

	ctx := context.Background()

	// Create source namespace
	sourceNS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "retry-source-",
		},
	}
	if err := tc.client.Create(ctx, sourceNS); err != nil {
		t.Fatalf("failed to create source namespace: %v", err)
	}
	defer tc.client.Delete(ctx, sourceNS)

	// Create target namespace
	targetNS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "retry-target-",
		},
	}
	if err := tc.client.Create(ctx, targetNS); err != nil {
		t.Fatalf("failed to create target namespace: %v", err)
	}
	defer tc.client.Delete(ctx, targetNS)

	// Step 1: Create a conflicting (unowned) Secret in the target namespace FIRST
	conflictingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "retry-secret",
			Namespace: targetNS.Name,
			// No replicated-from annotation - this is a foreign/unowned secret
		},
		Data: map[string][]byte{
			"foreign-key": []byte("foreign-value"),
		},
	}
	if err := tc.client.Create(ctx, conflictingSecret); err != nil {
		t.Fatalf("failed to create conflicting target secret: %v", err)
	}

	// Step 2: Create source Secret that wants to push to target namespace
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "retry-secret",
			Namespace: sourceNS.Name,
			Annotations: map[string]string{
				replicator.AnnotationReplicateTo: targetNS.Name,
			},
		},
		Data: map[string][]byte{
			"replicated-key": []byte("replicated-value"),
		},
	}
	if err := tc.client.Create(ctx, sourceSecret); err != nil {
		t.Fatalf("failed to create source secret: %v", err)
	}
	defer tc.client.Delete(ctx, sourceSecret)

	// Step 3: Verify the push was blocked - target should still have original data
	time.Sleep(3 * time.Second)

	var blockedTarget corev1.Secret
	if err := tc.client.Get(ctx, types.NamespacedName{
		Namespace: targetNS.Name,
		Name:      "retry-secret",
	}, &blockedTarget); err != nil {
		t.Fatalf("failed to get target secret: %v", err)
	}

	// Should still have original foreign data, not the replicated data
	if string(blockedTarget.Data["foreign-key"]) != "foreign-value" {
		t.Fatalf("conflicting target secret should not have been modified, got data: %v", blockedTarget.Data)
	}
	if _, hasReplicatedKey := blockedTarget.Data["replicated-key"]; hasReplicatedKey {
		t.Fatal("conflicting target secret should not have replicated data")
	}

	// Step 4: Delete the conflicting Secret
	if err := tc.client.Delete(ctx, conflictingSecret); err != nil {
		t.Fatalf("failed to delete conflicting secret: %v", err)
	}

	// Note: We do NOT wait for the secret to disappear here, because the controller's
	// findPushSourcesForTarget watch reacts so quickly that it may recreate the secret
	// (as a properly replicated one) before we can observe the deletion.

	// Step 5: The controller should now automatically retry and create the replicated Secret
	expectedData := map[string]string{
		"replicated-key": "replicated-value",
	}
	replicatedSecret, err := waitForSecretReplication(ctx, tc.client, types.NamespacedName{
		Namespace: targetNS.Name,
		Name:      "retry-secret",
	}, expectedData)
	if err != nil {
		t.Fatalf("push replication did not retry after conflicting secret was deleted: %v", err)
	}

	// Verify the replicated Secret has the correct annotations
	sourceRef := sourceNS.Name + "/retry-secret"
	if replicatedSecret.Annotations[replicator.AnnotationReplicatedFrom] != sourceRef {
		t.Errorf("expected replicated-from annotation %q, got %q",
			sourceRef, replicatedSecret.Annotations[replicator.AnnotationReplicatedFrom])
	}

	// Verify the replicated Secret has the correct data
	if string(replicatedSecret.Data["replicated-key"]) != "replicated-value" {
		t.Errorf("expected replicated-key=replicated-value, got %s",
			string(replicatedSecret.Data["replicated-key"]))
	}

	// Cleanup
	defer tc.client.Delete(ctx, replicatedSecret)
}
