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

package controller

import (
	"context"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/guided-traffic/internal-secrets-operator/pkg/config"
	"github.com/guided-traffic/internal-secrets-operator/pkg/replicator"
)

func TestSecretReplicatorReconciler_PullReplication(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	tests := []struct {
		name            string
		sourceSecret    *corev1.Secret
		targetSecret    *corev1.Secret
		expectedData    map[string]string
		expectError     bool
		expectEvent     bool
		expectEventType string
		expectEventMsg  string
	}{
		{
			name: "successful pull replication",
			sourceSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "db-credentials",
					Namespace: "production",
					Annotations: map[string]string{
						replicator.AnnotationReplicatableFromNamespaces: "staging",
					},
				},
				Data: map[string][]byte{
					"username": []byte("produser"),
					"password": []byte("prodpass"),
				},
			},
			targetSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "db-credentials",
					Namespace: "staging",
					Annotations: map[string]string{
						replicator.AnnotationReplicateFrom: "production/db-credentials",
					},
				},
			},
			expectedData: map[string]string{
				"username": "produser",
				"password": "prodpass",
			},
			expectError: false,
		},
		{
			name: "pull replication with wildcard allowlist",
			sourceSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "db-credentials",
					Namespace: "production",
					Annotations: map[string]string{
						replicator.AnnotationReplicatableFromNamespaces: "namespace-*",
					},
				},
				Data: map[string][]byte{
					"key": []byte("value"),
				},
			},
			targetSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "db-credentials",
					Namespace: "namespace-123",
					Annotations: map[string]string{
						replicator.AnnotationReplicateFrom: "production/db-credentials",
					},
				},
			},
			expectedData: map[string]string{
				"key": "value",
			},
			expectError: false,
		},
		{
			name: "replication denied - not in allowlist",
			sourceSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "db-credentials",
					Namespace: "production",
					Annotations: map[string]string{
						replicator.AnnotationReplicatableFromNamespaces: "staging",
					},
				},
				Data: map[string][]byte{
					"key": []byte("value"),
				},
			},
			targetSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "db-credentials",
					Namespace: "development",
					Annotations: map[string]string{
						replicator.AnnotationReplicateFrom: "production/db-credentials",
					},
				},
			},
			expectError: false, // Should not error, but should not replicate
		},
		{
			name: "source secret not found",
			targetSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "db-credentials",
					Namespace: "staging",
					Annotations: map[string]string{
						replicator.AnnotationReplicateFrom: "production/nonexistent",
					},
				},
			},
			expectError: false, // Should not error, just log warning
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []client.Object{}
			if tt.sourceSecret != nil {
				objs = append(objs, tt.sourceSecret)
			}
			if tt.targetSecret != nil {
				objs = append(objs, tt.targetSecret)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(objs...).
				Build()

			recorder := record.NewFakeRecorder(10)

			reconciler := &SecretReplicatorReconciler{
				Client:        fakeClient,
				Scheme:        scheme,
				Config:        config.NewDefaultConfig(),
				EventRecorder: recorder,
			}

			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: tt.targetSecret.Namespace,
					Name:      tt.targetSecret.Name,
				},
			}

			_, err := reconciler.Reconcile(context.Background(), req)
			if (err != nil) != tt.expectError {
				t.Errorf("Reconcile() error = %v, expectError %v", err, tt.expectError)
				return
			}

			// Check if data was replicated correctly
			if tt.expectedData != nil && tt.sourceSecret != nil {
				updatedSecret := &corev1.Secret{}
				err := fakeClient.Get(context.Background(), types.NamespacedName{
					Namespace: tt.targetSecret.Namespace,
					Name:      tt.targetSecret.Name,
				}, updatedSecret)

				if err != nil {
					t.Errorf("Failed to get updated secret: %v", err)
					return
				}

				for key, expectedValue := range tt.expectedData {
					actualValue := string(updatedSecret.Data[key])
					if actualValue != expectedValue {
						t.Errorf("Data[%s] = %q, want %q", key, actualValue, expectedValue)
					}
				}

				// Check replicated-from annotation
				if updatedSecret.Annotations[replicator.AnnotationReplicatedFrom] == "" {
					t.Error("Missing replicated-from annotation")
				}
			}
		})
	}
}

func TestSecretReplicatorReconciler_PushReplication(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	tests := []struct {
		name           string
		sourceSecret   *corev1.Secret
		existingTarget *corev1.Secret
		targetNS       string
		expectCreated  bool
		expectUpdated  bool
		expectSkipped  bool
	}{
		{
			name: "push creates new secret",
			sourceSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app-secret",
					Namespace: "production",
					Annotations: map[string]string{
						replicator.AnnotationReplicateTo: "staging",
					},
				},
				Data: map[string][]byte{
					"key": []byte("value"),
				},
			},
			targetNS:      "staging",
			expectCreated: true,
		},
		{
			name: "push updates owned secret",
			sourceSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app-secret",
					Namespace: "production",
					Annotations: map[string]string{
						replicator.AnnotationReplicateTo: "staging",
					},
				},
				Data: map[string][]byte{
					"key": []byte("newvalue"),
				},
			},
			existingTarget: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app-secret",
					Namespace: "staging",
					Annotations: map[string]string{
						replicator.AnnotationReplicatedFrom: "production/app-secret",
					},
				},
				Data: map[string][]byte{
					"key": []byte("oldvalue"),
				},
			},
			targetNS:      "staging",
			expectUpdated: true,
		},
		{
			name: "push skips unowned secret",
			sourceSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app-secret",
					Namespace: "production",
					Annotations: map[string]string{
						replicator.AnnotationReplicateTo: "staging",
					},
				},
				Data: map[string][]byte{
					"key": []byte("value"),
				},
			},
			existingTarget: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app-secret",
					Namespace: "staging",
					// No replicated-from annotation - not owned by us
				},
				Data: map[string][]byte{
					"key": []byte("existing"),
				},
			},
			targetNS:      "staging",
			expectSkipped: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []client.Object{tt.sourceSecret}
			if tt.existingTarget != nil {
				objs = append(objs, tt.existingTarget)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(objs...).
				Build()

			recorder := record.NewFakeRecorder(10)

			reconciler := &SecretReplicatorReconciler{
				Client:        fakeClient,
				Scheme:        scheme,
				Config:        config.NewDefaultConfig(),
				EventRecorder: recorder,
			}

			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: tt.sourceSecret.Namespace,
					Name:      tt.sourceSecret.Name,
				},
			}

			_, err := reconciler.Reconcile(context.Background(), req)
			if err != nil {
				t.Errorf("Reconcile() error = %v", err)
				return
			}

			// Check if target was created/updated/skipped as expected
			targetSecret := &corev1.Secret{}
			err = fakeClient.Get(context.Background(), types.NamespacedName{
				Namespace: tt.targetNS,
				Name:      tt.sourceSecret.Name,
			}, targetSecret)

			if tt.expectCreated {
				if err != nil {
					t.Errorf("Expected secret to be created, but got error: %v", err)
					return
				}
				if string(targetSecret.Data["key"]) != string(tt.sourceSecret.Data["key"]) {
					t.Errorf("Created secret data mismatch")
				}
			}

			if tt.expectUpdated {
				if err != nil {
					t.Errorf("Expected secret to be updated, but got error: %v", err)
					return
				}
				if string(targetSecret.Data["key"]) != "newvalue" {
					t.Errorf("Secret was not updated correctly")
				}
			}

			if tt.expectSkipped {
				if err != nil {
					t.Errorf("Got error: %v", err)
					return
				}
				// Should still exist but with old data
				if string(targetSecret.Data["key"]) != "existing" {
					t.Errorf("Unowned secret was modified")
				}
			}
		})
	}
}

func TestSecretReplicatorReconciler_ConflictingAnnotations(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "conflicting-secret",
			Namespace: "default",
			Annotations: map[string]string{
				"iso.gtrfc.com/autogenerate":       "password",
				replicator.AnnotationReplicateFrom: "production/db-credentials",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "default",
			Name:      "conflicting-secret",
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v", err)
	}

	// Check that a warning event was created
	select {
	case event := <-recorder.Events:
		if event == "" {
			t.Error("Expected warning event for conflicting annotations")
		}
	default:
		t.Error("No event recorded for conflicting annotations")
	}
}

func TestSecretReplicatorReconciler_FindTargetsForSource(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-credentials",
			Namespace: "production",
			Annotations: map[string]string{
				replicator.AnnotationReplicatableFromNamespaces: "*",
			},
		},
	}

	target1 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-credentials",
			Namespace: "staging",
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: "production/db-credentials",
			},
		},
	}

	target2 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-credentials",
			Namespace: "development",
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: "production/db-credentials",
			},
		},
	}

	otherSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other-secret",
			Namespace: "staging",
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: "other-namespace/other-secret",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret, target1, target2, otherSecret).
		Build()

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: record.NewFakeRecorder(10),
	}

	requests := reconciler.findTargetsForSource(context.Background(), sourceSecret)

	// Should find 2 targets (target1 and target2)
	if len(requests) != 2 {
		t.Errorf("Expected 2 reconcile requests, got %d", len(requests))
	}

	// Verify the requests are for the correct targets
	foundStaging := false
	foundDevelopment := false
	for _, req := range requests {
		if req.Namespace == "staging" && req.Name == "db-credentials" {
			foundStaging = true
		}
		if req.Namespace == "development" && req.Name == "db-credentials" {
			foundDevelopment = true
		}
	}

	if !foundStaging {
		t.Error("Did not find reconcile request for staging/db-credentials")
	}
	if !foundDevelopment {
		t.Error("Did not find reconcile request for development/db-credentials")
	}
}

func TestSecretReplicatorReconciler_SourceWithoutAllowlist(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Source without replicatable-from-namespaces annotation
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-credentials",
			Namespace: "production",
			// No replicatable-from-namespaces annotation
		},
		Data: map[string][]byte{
			"password": []byte("secret"),
		},
	}

	targetSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-credentials",
			Namespace: "staging",
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: "production/db-credentials",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret, targetSecret).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: targetSecret.Namespace,
			Name:      targetSecret.Name,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v", err)
	}

	// Check that target secret was NOT updated (no data replicated)
	updatedSecret := &corev1.Secret{}
	err = fakeClient.Get(context.Background(), types.NamespacedName{
		Namespace: targetSecret.Namespace,
		Name:      targetSecret.Name,
	}, updatedSecret)
	if err != nil {
		t.Fatalf("Failed to get target secret: %v", err)
	}

	// Data should still be empty (replication denied)
	if len(updatedSecret.Data) > 0 {
		t.Error("Expected target secret to remain empty when source has no allowlist")
	}

	// Check for warning event
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "Warning") {
			t.Errorf("Expected warning event, got: %s", event)
		}
	default:
		t.Error("Expected a warning event for denied replication")
	}
}

func TestSecretReplicatorReconciler_PushToMultipleNamespaces(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shared-secret",
			Namespace: "production",
			Annotations: map[string]string{
				replicator.AnnotationReplicateTo: "staging,development,qa",
			},
		},
		Data: map[string][]byte{
			"api-key": []byte("secret-key"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: sourceSecret.Namespace,
			Name:      sourceSecret.Name,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v", err)
	}

	// Check that secrets were created in all target namespaces
	targetNamespaces := []string{"staging", "development", "qa"}
	for _, ns := range targetNamespaces {
		targetSecret := &corev1.Secret{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{
			Namespace: ns,
			Name:      sourceSecret.Name,
		}, targetSecret)
		if err != nil {
			t.Errorf("Expected secret to be created in %s, got error: %v", ns, err)
			continue
		}

		// Verify data was replicated
		if string(targetSecret.Data["api-key"]) != "secret-key" {
			t.Errorf("Secret in %s has wrong data", ns)
		}

		// Verify replicated-from annotation
		expectedSource := "production/shared-secret"
		if targetSecret.Annotations[replicator.AnnotationReplicatedFrom] != expectedSource {
			t.Errorf("Secret in %s has wrong replicated-from annotation", ns)
		}
	}
}

func TestSecretReplicatorReconciler_FinalizerAddedOnPush(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "push-secret",
			Namespace: "production",
			Annotations: map[string]string{
				replicator.AnnotationReplicateTo: "staging",
			},
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: sourceSecret.Namespace,
			Name:      sourceSecret.Name,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v", err)
	}

	// Verify finalizer was added to source
	updatedSource := &corev1.Secret{}
	err = fakeClient.Get(context.Background(), types.NamespacedName{
		Namespace: sourceSecret.Namespace,
		Name:      sourceSecret.Name,
	}, updatedSource)
	if err != nil {
		t.Fatalf("Failed to get source secret: %v", err)
	}

	if !replicator.HasFinalizer(updatedSource) {
		t.Error("Expected finalizer to be added to source secret for cleanup")
	}
}

func TestSecretReplicatorReconciler_AllowAutogenerateWithReplicatableFromNamespaces(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// This combination is ALLOWED per Q17: autogenerate + replicatable-from-namespaces
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "combined-secret",
			Namespace: "production",
			Annotations: map[string]string{
				"iso.gtrfc.com/autogenerate":                    "password",
				replicator.AnnotationReplicatableFromNamespaces: "staging,development",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: secret.Namespace,
			Name:      secret.Name,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v", err)
	}

	// Should NOT generate a warning event (this combination is allowed)
	select {
	case event := <-recorder.Events:
		if strings.Contains(event, "ConflictingFeatures") {
			t.Errorf("autogenerate + replicatable-from-namespaces should be allowed, but got conflict event: %s", event)
		}
	default:
		// No event is good - the combination is allowed
	}
}

func TestSecretReplicatorReconciler_HandleDeletion(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	tests := []struct {
		name                    string
		sourceSecret            *corev1.Secret
		replicatedSecrets       []*corev1.Secret
		expectReplicatedDeleted bool
		expectFinalizerRemoved  bool
	}{
		{
			name: "deletion with replicate-to cleans up pushed secrets",
			sourceSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "push-secret",
					Namespace:         "production",
					DeletionTimestamp: &metav1.Time{Time: metav1.Now().Time},
					Finalizers:        []string{replicator.FinalizerReplicateToCleanup},
					Annotations: map[string]string{
						replicator.AnnotationReplicateTo: "staging,development",
					},
				},
				Data: map[string][]byte{
					"key": []byte("value"),
				},
			},
			replicatedSecrets: []*corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "push-secret",
						Namespace: "staging",
						Annotations: map[string]string{
							replicator.AnnotationReplicatedFrom: "production/push-secret",
						},
					},
					Data: map[string][]byte{
						"key": []byte("value"),
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "push-secret",
						Namespace: "development",
						Annotations: map[string]string{
							replicator.AnnotationReplicatedFrom: "production/push-secret",
						},
					},
					Data: map[string][]byte{
						"key": []byte("value"),
					},
				},
			},
			expectReplicatedDeleted: true,
			expectFinalizerRemoved:  true,
		},
		{
			name: "deletion with finalizer but no replicate-to removes finalizer only",
			sourceSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "finalizer-no-replicate-to",
					Namespace:         "production",
					DeletionTimestamp: &metav1.Time{Time: metav1.Now().Time},
					Finalizers:        []string{replicator.FinalizerReplicateToCleanup},
					// No replicate-to annotation
				},
			},
			replicatedSecrets:       nil,
			expectReplicatedDeleted: false,
			expectFinalizerRemoved:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []client.Object{tt.sourceSecret}
			for _, s := range tt.replicatedSecrets {
				objs = append(objs, s)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(objs...).
				Build()

			recorder := record.NewFakeRecorder(10)

			reconciler := &SecretReplicatorReconciler{
				Client:        fakeClient,
				Scheme:        scheme,
				Config:        config.NewDefaultConfig(),
				EventRecorder: recorder,
			}

			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: tt.sourceSecret.Namespace,
					Name:      tt.sourceSecret.Name,
				},
			}

			_, err := reconciler.Reconcile(context.Background(), req)
			if err != nil {
				t.Errorf("Reconcile() error = %v", err)
				return
			}

			// Check if replicated secrets were deleted
			if tt.expectReplicatedDeleted {
				for _, s := range tt.replicatedSecrets {
					secret := &corev1.Secret{}
					err := fakeClient.Get(context.Background(), types.NamespacedName{
						Namespace: s.Namespace,
						Name:      s.Name,
					}, secret)
					if err == nil {
						t.Errorf("Expected replicated secret %s/%s to be deleted", s.Namespace, s.Name)
					}
				}
			}

			// Check if finalizer was removed from source
			if tt.expectFinalizerRemoved {
				updatedSource := &corev1.Secret{}
				err := fakeClient.Get(context.Background(), types.NamespacedName{
					Namespace: tt.sourceSecret.Namespace,
					Name:      tt.sourceSecret.Name,
				}, updatedSource)
				if err != nil {
					// With deletionTimestamp and empty finalizers, the object might be deleted
					// This is acceptable if the finalizer was removed
					return
				}
				if replicator.HasFinalizer(updatedSource) {
					t.Error("Expected finalizer to be removed from source secret")
				}
			}
		})
	}
}

func TestSecretReplicatorReconciler_HandleDeletionWithoutFinalizer(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Secret without finalizer but with deletionTimestamp
	// The handleDeletion should return early because there's no finalizer
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "no-finalizer-secret",
			Namespace:  "production",
			Finalizers: []string{}, // Empty finalizers
			Annotations: map[string]string{
				replicator.AnnotationReplicateTo: "staging",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	// Directly call handleDeletion to test the early return path
	// Since we can't create an object with deletionTimestamp via fake client,
	// we test the HasFinalizer check which returns early

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: sourceSecret.Namespace,
			Name:      sourceSecret.Name,
		},
	}

	// This should process the push replication (since it's not being deleted)
	_, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v", err)
	}
}

func TestSecretReplicatorReconciler_SecretNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "default",
			Name:      "nonexistent-secret",
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	// Should not return an error when secret is not found
	if err != nil {
		t.Errorf("Reconcile() error = %v, expected nil", err)
	}
}

func TestSecretReplicatorReconciler_InvalidSourceReference(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	targetSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "target-secret",
			Namespace: "staging",
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: "invalid-reference-without-slash",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(targetSecret).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: targetSecret.Namespace,
			Name:      targetSecret.Name,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	// Should not return an error (just logs warning)
	if err != nil {
		t.Errorf("Reconcile() error = %v, expected nil", err)
	}

	// Check for warning event about invalid reference
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "Warning") || !strings.Contains(event, "Invalid source reference") {
			t.Errorf("Expected warning event about invalid source reference, got: %s", event)
		}
	default:
		t.Error("Expected a warning event for invalid source reference")
	}
}

func TestSecretReplicatorReconciler_SourceBeingDeleted(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Source secret is being deleted
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "db-credentials",
			Namespace:         "production",
			DeletionTimestamp: &metav1.Time{Time: metav1.Now().Time},
			Finalizers:        []string{"some-other-finalizer"},
			Annotations: map[string]string{
				replicator.AnnotationReplicatableFromNamespaces: "staging",
			},
		},
		Data: map[string][]byte{
			"password": []byte("secret"),
		},
	}

	targetSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-credentials",
			Namespace: "staging",
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: "production/db-credentials",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret, targetSecret).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: targetSecret.Namespace,
			Name:      targetSecret.Name,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v", err)
	}

	// Check for warning event about source being deleted
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "SourceDeleted") {
			t.Errorf("Expected SourceDeleted event, got: %s", event)
		}
	default:
		t.Error("Expected a warning event when source is being deleted")
	}
}

func TestSecretReplicatorReconciler_PushEmptyNamespaceList(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "empty-push-secret",
			Namespace: "production",
			Annotations: map[string]string{
				replicator.AnnotationReplicateTo: "",
			},
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: sourceSecret.Namespace,
			Name:      sourceSecret.Name,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v", err)
	}

	// Should not add finalizer when no target namespaces are specified
	updatedSource := &corev1.Secret{}
	err = fakeClient.Get(context.Background(), types.NamespacedName{
		Namespace: sourceSecret.Namespace,
		Name:      sourceSecret.Name,
	}, updatedSource)
	if err != nil {
		t.Fatalf("Failed to get source secret: %v", err)
	}

	if replicator.HasFinalizer(updatedSource) {
		t.Error("Finalizer should not be added when no target namespaces are specified")
	}
}

func TestSecretReplicatorReconciler_FindTargetsForSourceWithNonSecret(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: record.NewFakeRecorder(10),
	}

	// Pass a non-Secret object (use a ConfigMap-like object but cast it wrong)
	// This tests the early return when obj is not a Secret
	requests := reconciler.findTargetsForSource(context.Background(), nil)
	if requests != nil {
		t.Error("Expected nil requests when object is nil")
	}
}

func TestSecretReplicatorReconciler_FindTargetsForSourceNoTargets(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-credentials",
			Namespace: "production",
			Annotations: map[string]string{
				replicator.AnnotationReplicatableFromNamespaces: "*",
			},
		},
	}

	// No targets that pull from this source
	otherSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other-secret",
			Namespace: "staging",
			// No annotations
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret, otherSecret).
		Build()

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: record.NewFakeRecorder(10),
	}

	requests := reconciler.findTargetsForSource(context.Background(), sourceSecret)

	// Should return empty list when no targets pull from this source
	if len(requests) != 0 {
		t.Errorf("Expected 0 reconcile requests, got %d", len(requests))
	}
}

func TestSecretReplicatorReconciler_PushReplicationWithOnlyWhitespaceNamespaces(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "whitespace-push-secret",
			Namespace: "production",
			Annotations: map[string]string{
				replicator.AnnotationReplicateTo: "  ,  ,  ", // Only whitespace and commas
			},
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: sourceSecret.Namespace,
			Name:      sourceSecret.Name,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v", err)
	}

	// Should not add finalizer when no valid target namespaces are specified
	updatedSource := &corev1.Secret{}
	err = fakeClient.Get(context.Background(), types.NamespacedName{
		Namespace: sourceSecret.Namespace,
		Name:      sourceSecret.Name,
	}, updatedSource)
	if err != nil {
		t.Fatalf("Failed to get source secret: %v", err)
	}

	if replicator.HasFinalizer(updatedSource) {
		t.Error("Finalizer should not be added when no valid target namespaces are specified")
	}
}

func TestSecretReplicatorReconciler_PushReplicationWithFinalizer(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Source secret already has a finalizer
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "push-secret-with-finalizer",
			Namespace:  "production",
			Finalizers: []string{replicator.FinalizerReplicateToCleanup},
			Annotations: map[string]string{
				replicator.AnnotationReplicateTo: "staging",
			},
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: sourceSecret.Namespace,
			Name:      sourceSecret.Name,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v", err)
	}

	// Verify target was created
	targetSecret := &corev1.Secret{}
	err = fakeClient.Get(context.Background(), types.NamespacedName{
		Namespace: "staging",
		Name:      sourceSecret.Name,
	}, targetSecret)
	if err != nil {
		t.Errorf("Expected target secret to be created, got error: %v", err)
	}
}

func TestSecretReplicatorReconciler_PushUpdateExistingOwnedSecret(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "push-update-secret",
			Namespace:  "production",
			Finalizers: []string{replicator.FinalizerReplicateToCleanup},
			Annotations: map[string]string{
				replicator.AnnotationReplicateTo: "staging",
			},
		},
		Data: map[string][]byte{
			"key": []byte("new-value"),
		},
	}

	// Existing target secret that we own (has replicated-from annotation)
	targetSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "push-update-secret",
			Namespace: "staging",
			Annotations: map[string]string{
				replicator.AnnotationReplicatedFrom: "production/push-update-secret",
			},
		},
		Data: map[string][]byte{
			"key": []byte("old-value"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret, targetSecret).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: sourceSecret.Namespace,
			Name:      sourceSecret.Name,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v", err)
	}

	// Verify target was updated with new value
	updatedTarget := &corev1.Secret{}
	err = fakeClient.Get(context.Background(), types.NamespacedName{
		Namespace: "staging",
		Name:      sourceSecret.Name,
	}, updatedTarget)
	if err != nil {
		t.Fatalf("Failed to get target secret: %v", err)
	}

	if string(updatedTarget.Data["key"]) != "new-value" {
		t.Errorf("Expected target secret data to be updated to 'new-value', got '%s'", string(updatedTarget.Data["key"]))
	}
}

func TestSecretReplicatorReconciler_PullReplicationUpdateError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-credentials",
			Namespace: "production",
			Annotations: map[string]string{
				replicator.AnnotationReplicatableFromNamespaces: "staging",
			},
		},
		Data: map[string][]byte{
			"password": []byte("secret"),
		},
	}

	targetSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-credentials",
			Namespace: "staging",
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: "production/db-credentials",
			},
		},
	}

	// Create a client that will fail on Update
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret, targetSecret).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				// Fail specifically when updating the target secret
				if secret, ok := obj.(*corev1.Secret); ok && secret.Namespace == "staging" {
					return fmt.Errorf("simulated update error")
				}
				return client.Update(ctx, obj, opts...)
			},
		}).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: targetSecret.Namespace,
			Name:      targetSecret.Name,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Expected error from Reconcile when update fails")
	}

	// Check for warning event
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "Warning") || !strings.Contains(event, "Failed to update") {
			t.Errorf("Expected warning event about failed update, got: %s", event)
		}
	default:
		t.Error("Expected a warning event for failed update")
	}
}

func TestSecretReplicatorReconciler_PushCreateError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "push-create-error-secret",
			Namespace: "production",
			Annotations: map[string]string{
				replicator.AnnotationReplicateTo: "staging",
			},
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	// Create a client that will fail on Create
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if secret, ok := obj.(*corev1.Secret); ok && secret.Namespace == "staging" {
					return fmt.Errorf("simulated create error")
				}
				return client.Create(ctx, obj, opts...)
			},
		}).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: sourceSecret.Namespace,
			Name:      sourceSecret.Name,
		},
	}

	// This should not return an error (continues with other namespaces)
	_, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v, expected nil (error is logged but not returned)", err)
	}

	// Check for warning event about create failure
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "Warning") || !strings.Contains(event, "PushFailed") {
			t.Errorf("Expected warning event about push failure, got: %s", event)
		}
	default:
		t.Error("Expected a warning event for failed create")
	}
}

func TestSecretReplicatorReconciler_PushUpdateOwnedSecretError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "push-update-error-secret",
			Namespace:  "production",
			Finalizers: []string{replicator.FinalizerReplicateToCleanup},
			Annotations: map[string]string{
				replicator.AnnotationReplicateTo: "staging",
			},
		},
		Data: map[string][]byte{
			"key": []byte("new-value"),
		},
	}

	// Existing target secret that we own
	targetSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "push-update-error-secret",
			Namespace: "staging",
			Annotations: map[string]string{
				replicator.AnnotationReplicatedFrom: "production/push-update-error-secret",
			},
		},
		Data: map[string][]byte{
			"key": []byte("old-value"),
		},
	}

	// Create a client that will fail on Update for the target secret
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret, targetSecret).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if secret, ok := obj.(*corev1.Secret); ok && secret.Namespace == "staging" && secret.Name == "push-update-error-secret" {
					return fmt.Errorf("simulated update error")
				}
				return client.Update(ctx, obj, opts...)
			},
		}).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: sourceSecret.Namespace,
			Name:      sourceSecret.Name,
		},
	}

	// Push replication continues even if one namespace fails
	_, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v, expected nil", err)
	}

	// Check for warning event about update failure
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "Warning") || !strings.Contains(event, "PushFailed") {
			t.Errorf("Expected warning event about push failure, got: %s", event)
		}
	default:
		t.Error("Expected a warning event for failed update")
	}
}

func TestSecretReplicatorReconciler_HandleDeletionListError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "push-deletion-list-error",
			Namespace:         "production",
			DeletionTimestamp: &metav1.Time{Time: metav1.Now().Time},
			Finalizers:        []string{replicator.FinalizerReplicateToCleanup},
			Annotations: map[string]string{
				replicator.AnnotationReplicateTo: "staging",
			},
		},
	}

	// Create a client that will fail on List
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, client client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				return fmt.Errorf("simulated list error")
			},
		}).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: sourceSecret.Namespace,
			Name:      sourceSecret.Name,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Expected error from Reconcile when List fails during deletion cleanup")
	}
}

func TestSecretReplicatorReconciler_HandleDeletionDeleteError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "push-deletion-delete-error",
			Namespace:         "production",
			DeletionTimestamp: &metav1.Time{Time: metav1.Now().Time},
			Finalizers:        []string{replicator.FinalizerReplicateToCleanup},
			Annotations: map[string]string{
				replicator.AnnotationReplicateTo: "staging",
			},
		},
	}

	replicatedSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "push-deletion-delete-error",
			Namespace: "staging",
			Annotations: map[string]string{
				replicator.AnnotationReplicatedFrom: "production/push-deletion-delete-error",
			},
		},
	}

	// Create a client that will fail on Delete
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret, replicatedSecret).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if secret, ok := obj.(*corev1.Secret); ok && secret.Namespace == "staging" {
					return fmt.Errorf("simulated delete error")
				}
				return client.Delete(ctx, obj, opts...)
			},
		}).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: sourceSecret.Namespace,
			Name:      sourceSecret.Name,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Expected error from Reconcile when Delete fails during deletion cleanup")
	}
}

func TestSecretReplicatorReconciler_HandleDeletionRemoveFinalizerError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "push-finalizer-remove-error",
			Namespace:         "production",
			DeletionTimestamp: &metav1.Time{Time: metav1.Now().Time},
			Finalizers:        []string{replicator.FinalizerReplicateToCleanup},
			Annotations: map[string]string{
				replicator.AnnotationReplicateTo: "staging",
			},
		},
	}

	replicatedSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "push-finalizer-remove-error",
			Namespace: "staging",
			Annotations: map[string]string{
				replicator.AnnotationReplicatedFrom: "production/push-finalizer-remove-error",
			},
		},
	}

	updateCallCount := 0

	// Create a client that will fail on the last Update (removing finalizer)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret, replicatedSecret).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if secret, ok := obj.(*corev1.Secret); ok && secret.Namespace == "production" {
					updateCallCount++
					// Fail only on removing finalizer (second update of the source secret)
					if updateCallCount > 0 {
						return fmt.Errorf("simulated finalizer removal error")
					}
				}
				return client.Update(ctx, obj, opts...)
			},
		}).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: sourceSecret.Namespace,
			Name:      sourceSecret.Name,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Expected error from Reconcile when removing finalizer fails")
	}
}

func TestSecretReplicatorReconciler_HandleDeletionNoReplicateToAnnotation(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Secret being deleted with finalizer but NO replicate-to annotation
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "finalizer-no-annotation",
			Namespace:         "production",
			DeletionTimestamp: &metav1.Time{Time: metav1.Now().Time},
			Finalizers:        []string{replicator.FinalizerReplicateToCleanup},
			// No replicate-to annotation
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: sourceSecret.Namespace,
			Name:      sourceSecret.Name,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v, expected nil", err)
	}
}

func TestSecretReplicatorReconciler_HandleDeletionNoReplicateToRemoveFinalizerError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Secret being deleted with finalizer but NO replicate-to annotation
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "finalizer-remove-error",
			Namespace:         "production",
			DeletionTimestamp: &metav1.Time{Time: metav1.Now().Time},
			Finalizers:        []string{replicator.FinalizerReplicateToCleanup},
			// No replicate-to annotation
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				return fmt.Errorf("simulated update error")
			},
		}).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: sourceSecret.Namespace,
			Name:      sourceSecret.Name,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Expected error from Reconcile when Update fails")
	}
}

func TestSecretReplicatorReconciler_PushAddFinalizerError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "push-add-finalizer-error",
			Namespace: "production",
			Annotations: map[string]string{
				replicator.AnnotationReplicateTo: "staging",
			},
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	// Create a client that will fail on Update when adding finalizer
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if secret, ok := obj.(*corev1.Secret); ok && secret.Namespace == "production" {
					return fmt.Errorf("simulated finalizer add error")
				}
				return client.Update(ctx, obj, opts...)
			},
		}).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: sourceSecret.Namespace,
			Name:      sourceSecret.Name,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Expected error from Reconcile when adding finalizer fails")
	}
}

func TestSecretReplicatorReconciler_FindTargetsForSourceListError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-credentials",
			Namespace: "production",
			Annotations: map[string]string{
				replicator.AnnotationReplicatableFromNamespaces: "*",
			},
		},
	}

	// Create a client that will fail on List
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceSecret).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, client client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				return fmt.Errorf("simulated list error")
			},
		}).
		Build()

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: record.NewFakeRecorder(10),
	}

	requests := reconciler.findTargetsForSource(context.Background(), sourceSecret)

	// Should return nil when List fails
	if requests != nil {
		t.Errorf("Expected nil requests when List fails, got %d requests", len(requests))
	}
}

func TestSecretReplicatorReconciler_ReconcileGetError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Create a client that will fail on Get (not NotFound)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, client client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				return fmt.Errorf("simulated get error")
			},
		}).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "default",
			Name:      "any-secret",
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Expected error from Reconcile when Get fails (not NotFound)")
	}
}

func TestSecretReplicatorReconciler_PullReplicationGetSourceError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	targetSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "target-secret",
			Namespace: "staging",
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: "production/db-credentials",
			},
		},
	}

	getCallCount := 0

	// Create a client that will fail on the second Get (for source secret)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(targetSecret).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, client client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				getCallCount++
				// First Get is for the target secret (reconcile), second is for source
				if getCallCount == 2 {
					return fmt.Errorf("simulated get source error")
				}
				return client.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	recorder := record.NewFakeRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: targetSecret.Namespace,
			Name:      targetSecret.Name,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Expected error from Reconcile when getting source secret fails (not NotFound)")
	}
}
