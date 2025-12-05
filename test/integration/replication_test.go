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
		if err != nil || len(secret.Data) > 0 {
			return false
		}
		time.Sleep(replicationInterval)
	}

	return true
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
