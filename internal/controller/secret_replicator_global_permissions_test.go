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
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/guided-traffic/internal-secrets-operator/pkg/config"
	"github.com/guided-traffic/internal-secrets-operator/pkg/replicator"
)

// configWithGlobalPermissions returns a default config with the given global pull-based permissions
func configWithGlobalPermissions(perms ...config.GlobalPullBasedPermission) *config.Config {
	cfg := config.NewDefaultConfig()
	cfg.GlobalPullBasedPermissions = perms
	return cfg
}

func TestSecretReplicatorReconciler_PullReplicationWithGlobalPermissions(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	tests := []struct {
		name         string
		permissions  []config.GlobalPullBasedPermission
		sourceSecret *corev1.Secret
		targetSecret *corev1.Secret
		expectedData map[string]string
		expectDenied bool
	}{
		{
			name: "global permission allows pull without source annotation",
			permissions: []config.GlobalPullBasedPermission{
				{
					FromNamespace:     "production",
					ToNamespace:       "staging",
					ValidationPattern: "db-*",
					AllowSecret:       true,
				},
			},
			sourceSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "db-credentials",
					Namespace: "production",
					// No replicatable-from-namespaces annotation
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
		},
		{
			name: "global permission allows pull when annotation denies target namespace",
			permissions: []config.GlobalPullBasedPermission{
				{
					FromNamespace:     "production",
					ToNamespace:       "staging",
					ValidationPattern: "*",
					AllowSecret:       true,
				},
			},
			sourceSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "db-credentials",
					Namespace: "production",
					Annotations: map[string]string{
						// Allowlist does NOT include staging
						replicator.AnnotationReplicatableFromNamespaces: "other-namespace",
					},
				},
				Data: map[string][]byte{"key": []byte("value")},
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
			expectedData: map[string]string{"key": "value"},
		},
		{
			name: "denied - source name does not match validationPattern",
			permissions: []config.GlobalPullBasedPermission{
				{
					FromNamespace:     "production",
					ToNamespace:       "staging",
					ValidationPattern: "db-*",
					AllowSecret:       true,
				},
			},
			sourceSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app-secret",
					Namespace: "production",
				},
				Data: map[string][]byte{"key": []byte("value")},
			},
			targetSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app-secret",
					Namespace: "staging",
					Annotations: map[string]string{
						replicator.AnnotationReplicateFrom: "production/app-secret",
					},
				},
			},
			expectDenied: true,
		},
		{
			name: "denied - permission only allows configmaps",
			permissions: []config.GlobalPullBasedPermission{
				{
					FromNamespace:     "production",
					ToNamespace:       "staging",
					ValidationPattern: "*",
					AllowConfigMap:    true,
					AllowSecret:       false,
				},
			},
			sourceSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "db-credentials",
					Namespace: "production",
				},
				Data: map[string][]byte{"key": []byte("value")},
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
			expectDenied: true,
		},
		{
			name: "denied - target namespace not covered by permission",
			permissions: []config.GlobalPullBasedPermission{
				{
					FromNamespace:     "production",
					ToNamespace:       "staging",
					ValidationPattern: "*",
					AllowSecret:       true,
				},
			},
			sourceSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "db-credentials",
					Namespace: "production",
				},
				Data: map[string][]byte{"key": []byte("value")},
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
			expectDenied: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.sourceSecret, tt.targetSecret).
				Build()

			recorder := NewTestEventRecorder(10)

			reconciler := &SecretReplicatorReconciler{
				Client:        fakeClient,
				Scheme:        scheme,
				Config:        configWithGlobalPermissions(tt.permissions...),
				EventRecorder: recorder,
			}

			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: tt.targetSecret.Namespace,
					Name:      tt.targetSecret.Name,
				},
			}

			_, err := reconciler.Reconcile(context.Background(), req)
			if err != nil {
				t.Fatalf("Reconcile() error = %v", err)
			}

			updatedSecret := &corev1.Secret{}
			if err := fakeClient.Get(context.Background(), types.NamespacedName{
				Namespace: tt.targetSecret.Namespace,
				Name:      tt.targetSecret.Name,
			}, updatedSecret); err != nil {
				t.Fatalf("Failed to get target secret: %v", err)
			}

			if tt.expectDenied {
				if len(updatedSecret.Data) > 0 {
					t.Error("Expected target secret to remain empty when replication is denied")
				}
				select {
				case event := <-recorder.Events:
					if !strings.Contains(event, "Warning") || !strings.Contains(event, "Replication not allowed") {
						t.Errorf("Expected warning event about denied replication, got: %s", event)
					}
				default:
					t.Error("Expected a warning event for denied replication")
				}
				return
			}

			for key, want := range tt.expectedData {
				if got := string(updatedSecret.Data[key]); got != want {
					t.Errorf("Data[%s] = %q, want %q", key, got, want)
				}
			}
			if updatedSecret.Annotations[replicator.AnnotationReplicatedFrom] == "" {
				t.Error("Missing replicated-from annotation")
			}
		})
	}
}

func TestSecretReplicatorReconciler_FindTargetsForGlobalPermissionSource(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Source WITHOUT any annotation - only covered by global permission
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-credentials",
			Namespace: "production",
		},
	}

	target := &corev1.Secret{
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
		WithObjects(sourceSecret, target).
		Build()

	reconciler := &SecretReplicatorReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Config: configWithGlobalPermissions(config.GlobalPullBasedPermission{
			FromNamespace:     "production",
			ToNamespace:       "staging",
			ValidationPattern: "db-*",
			AllowSecret:       true,
		}),
		EventRecorder: NewTestEventRecorder(10),
	}

	// findTargetsForSource must find the target for a source that is only
	// covered by a global permission (used by the source watch)
	requests := reconciler.findTargetsForSource(context.Background(), sourceSecret)
	if len(requests) != 1 {
		t.Fatalf("Expected 1 reconcile request, got %d", len(requests))
	}
	if requests[0].Namespace != "staging" || requests[0].Name != "db-credentials" {
		t.Errorf("Unexpected request: %+v", requests[0])
	}
}

func TestSecretReplicatorReconciler_NilConfigPermissionsDenied(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// No annotation on source, no global permissions configured
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-credentials",
			Namespace: "production",
		},
		Data: map[string][]byte{"key": []byte("value")},
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

	recorder := NewTestEventRecorder(10)

	reconciler := &SecretReplicatorReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Config:        config.NewDefaultConfig(),
		EventRecorder: recorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "staging", Name: "db-credentials"},
	}

	if _, err := reconciler.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	updated := &corev1.Secret{}
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(targetSecret), updated); err != nil {
		t.Fatalf("Failed to get target secret: %v", err)
	}
	if len(updated.Data) > 0 {
		t.Error("Expected replication to be denied without annotation and without global permissions")
	}
}
