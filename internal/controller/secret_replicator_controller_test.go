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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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
