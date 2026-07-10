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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/guided-traffic/internal-secrets-operator/pkg/config"
	"github.com/guided-traffic/internal-secrets-operator/pkg/replicator"
)

func newConfigMapReconciler(c client.Client, scheme *runtime.Scheme, cfg *config.Config, recorder *TestEventRecorder) *ConfigMapReplicatorReconciler {
	return &ConfigMapReplicatorReconciler{
		Client:        c,
		Scheme:        scheme,
		Config:        cfg,
		EventRecorder: recorder,
	}
}

func TestConfigMapReplicatorReconciler_PullReplication(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	tests := []struct {
		name           string
		permissions    []config.GlobalPullBasedPermission
		sourceCM       *corev1.ConfigMap
		targetCM       *corev1.ConfigMap
		expectedData   map[string]string
		expectedBinary map[string][]byte
		expectDenied   bool
	}{
		{
			name: "pull via source annotation (mutual consent)",
			sourceCM: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ca-bundle",
					Namespace: "garden",
					Annotations: map[string]string{
						replicator.AnnotationReplicatableFromNamespaces: "shoot-a",
					},
				},
				Data: map[string]string{"ca.crt": "cert-content"},
			},
			targetCM: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ca-bundle",
					Namespace: "shoot-a",
					Annotations: map[string]string{
						replicator.AnnotationReplicateFrom: "garden/ca-bundle",
					},
				},
			},
			expectedData: map[string]string{"ca.crt": "cert-content"},
		},
		{
			name: "pull via global permission without source annotation",
			permissions: []config.GlobalPullBasedPermission{
				{
					FromNamespace:     "garden",
					ToNamespace:       "shoot-a,shoot-b",
					ValidationPattern: "ca-*",
					AllowConfigMap:    true,
				},
			},
			sourceCM: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ca-bundle",
					Namespace: "garden",
					// No annotations - source cannot be modified
				},
				Data:       map[string]string{"ca.crt": "cert-content"},
				BinaryData: map[string][]byte{"blob": {0xCA, 0xFE}},
			},
			targetCM: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ca-bundle",
					Namespace: "shoot-a",
					Annotations: map[string]string{
						replicator.AnnotationReplicateFrom: "garden/ca-bundle",
					},
				},
			},
			expectedData:   map[string]string{"ca.crt": "cert-content"},
			expectedBinary: map[string][]byte{"blob": {0xCA, 0xFE}},
		},
		{
			name: "denied - no annotation and no global permission",
			sourceCM: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ca-bundle",
					Namespace: "garden",
				},
				Data: map[string]string{"ca.crt": "cert-content"},
			},
			targetCM: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ca-bundle",
					Namespace: "shoot-a",
					Annotations: map[string]string{
						replicator.AnnotationReplicateFrom: "garden/ca-bundle",
					},
				},
			},
			expectDenied: true,
		},
		{
			name: "denied - permission only allows secrets",
			permissions: []config.GlobalPullBasedPermission{
				{
					FromNamespace:     "garden",
					ToNamespace:       "shoot-a",
					ValidationPattern: "*",
					AllowSecret:       true,
					AllowConfigMap:    false,
				},
			},
			sourceCM: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ca-bundle",
					Namespace: "garden",
				},
				Data: map[string]string{"ca.crt": "cert-content"},
			},
			targetCM: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ca-bundle",
					Namespace: "shoot-a",
					Annotations: map[string]string{
						replicator.AnnotationReplicateFrom: "garden/ca-bundle",
					},
				},
			},
			expectDenied: true,
		},
		{
			name: "denied - source name does not match validationPattern",
			permissions: []config.GlobalPullBasedPermission{
				{
					FromNamespace:     "garden",
					ToNamespace:       "shoot-a",
					ValidationPattern: "ca-*",
					AllowConfigMap:    true,
				},
			},
			sourceCM: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "other-config",
					Namespace: "garden",
				},
				Data: map[string]string{"key": "value"},
			},
			targetCM: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "other-config",
					Namespace: "shoot-a",
					Annotations: map[string]string{
						replicator.AnnotationReplicateFrom: "garden/other-config",
					},
				},
			},
			expectDenied: true,
		},
		{
			name: "existing target data is overwritten on pull",
			permissions: []config.GlobalPullBasedPermission{
				{
					FromNamespace:     "garden",
					ToNamespace:       "shoot-a",
					ValidationPattern: "*",
					AllowConfigMap:    true,
				},
			},
			sourceCM: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app-config",
					Namespace: "garden",
				},
				Data: map[string]string{"setting": "new-value"},
			},
			targetCM: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app-config",
					Namespace: "shoot-a",
					Annotations: map[string]string{
						replicator.AnnotationReplicateFrom: "garden/app-config",
					},
				},
				Data: map[string]string{"setting": "old-value"},
			},
			expectedData: map[string]string{"setting": "new-value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.sourceCM, tt.targetCM).
				Build()

			recorder := NewTestEventRecorder(10)
			reconciler := newConfigMapReconciler(fakeClient, scheme, configWithGlobalPermissions(tt.permissions...), recorder)

			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: tt.targetCM.Namespace,
					Name:      tt.targetCM.Name,
				},
			}

			_, err := reconciler.Reconcile(context.Background(), req)
			if err != nil {
				t.Fatalf("Reconcile() error = %v", err)
			}

			updated := &corev1.ConfigMap{}
			if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(tt.targetCM), updated); err != nil {
				t.Fatalf("Failed to get target ConfigMap: %v", err)
			}

			if tt.expectDenied {
				if updated.Annotations[replicator.AnnotationReplicatedFrom] != "" {
					t.Error("Expected no replicated-from annotation when replication is denied")
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
				if got := updated.Data[key]; got != want {
					t.Errorf("Data[%s] = %q, want %q", key, got, want)
				}
			}
			for key, want := range tt.expectedBinary {
				if got := updated.BinaryData[key]; string(got) != string(want) {
					t.Errorf("BinaryData[%s] = %v, want %v", key, got, want)
				}
			}
			wantRef := fmt.Sprintf("%s/%s", tt.sourceCM.Namespace, tt.sourceCM.Name)
			if got := updated.Annotations[replicator.AnnotationReplicatedFrom]; got != wantRef {
				t.Errorf("replicated-from = %q, want %q", got, wantRef)
			}
		})
	}
}

func TestConfigMapReplicatorReconciler_SourceNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	targetCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-bundle",
			Namespace: "shoot-a",
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: "garden/nonexistent",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(targetCM).Build()
	recorder := NewTestEventRecorder(10)
	reconciler := newConfigMapReconciler(fakeClient, scheme, config.NewDefaultConfig(), recorder)

	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(targetCM)}
	if _, err := reconciler.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile() error = %v, expected nil", err)
	}

	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "Warning") || !strings.Contains(event, "not found") {
			t.Errorf("Expected warning event about missing source, got: %s", event)
		}
	default:
		t.Error("Expected a warning event for missing source")
	}
}

func TestConfigMapReplicatorReconciler_InvalidSourceReference(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	targetCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-bundle",
			Namespace: "shoot-a",
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: "invalid-reference-without-slash",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(targetCM).Build()
	recorder := NewTestEventRecorder(10)
	reconciler := newConfigMapReconciler(fakeClient, scheme, config.NewDefaultConfig(), recorder)

	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(targetCM)}
	if _, err := reconciler.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile() error = %v, expected nil", err)
	}

	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "Warning") || !strings.Contains(event, "Invalid source reference") {
			t.Errorf("Expected warning event about invalid source reference, got: %s", event)
		}
	default:
		t.Error("Expected a warning event for invalid source reference")
	}
}

func TestConfigMapReplicatorReconciler_ConfigMapNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := newConfigMapReconciler(fakeClient, scheme, config.NewDefaultConfig(), NewTestEventRecorder(10))

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "nonexistent"},
	}
	if _, err := reconciler.Reconcile(context.Background(), req); err != nil {
		t.Errorf("Reconcile() error = %v, expected nil", err)
	}
}

func TestConfigMapReplicatorReconciler_NoAnnotationsIsNoOp(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "plain-cm", Namespace: "default"},
		Data:       map[string]string{"key": "value"},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm).Build()
	recorder := NewTestEventRecorder(10)
	reconciler := newConfigMapReconciler(fakeClient, scheme, config.NewDefaultConfig(), recorder)

	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(cm)}
	if _, err := reconciler.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	updated := &corev1.ConfigMap{}
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(cm), updated); err != nil {
		t.Fatalf("Failed to get ConfigMap: %v", err)
	}
	if updated.Data["key"] != "value" {
		t.Error("ConfigMap without replication annotations must not be modified")
	}

	select {
	case event := <-recorder.Events:
		t.Errorf("Expected no events, got: %s", event)
	default:
	}
}

func TestConfigMapReplicatorReconciler_SourceBeingDeleted(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	now := metav1.Now()
	sourceCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "ca-bundle",
			Namespace:         "garden",
			DeletionTimestamp: &now,
			Finalizers:        []string{"some-other-finalizer"},
			Annotations: map[string]string{
				replicator.AnnotationReplicatableFromNamespaces: "shoot-a",
			},
		},
		Data: map[string]string{"ca.crt": "cert-content"},
	}

	targetCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-bundle",
			Namespace: "shoot-a",
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: "garden/ca-bundle",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sourceCM, targetCM).Build()
	recorder := NewTestEventRecorder(10)
	reconciler := newConfigMapReconciler(fakeClient, scheme, config.NewDefaultConfig(), recorder)

	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(targetCM)}
	if _, err := reconciler.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	// Target keeps last known data (stays empty here), source deletion event recorded
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "SourceDeleted") {
			t.Errorf("Expected SourceDeleted event, got: %s", event)
		}
	default:
		t.Error("Expected a warning event when source is being deleted")
	}
}

func TestConfigMapReplicatorReconciler_TargetBeingDeletedIsNoOp(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	now := metav1.Now()
	targetCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "ca-bundle",
			Namespace:         "shoot-a",
			DeletionTimestamp: &now,
			Finalizers:        []string{"some-other-finalizer"},
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: "garden/ca-bundle",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(targetCM).Build()
	recorder := NewTestEventRecorder(10)
	reconciler := newConfigMapReconciler(fakeClient, scheme, config.NewDefaultConfig(), recorder)

	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(targetCM)}
	if _, err := reconciler.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	select {
	case event := <-recorder.Events:
		t.Errorf("Expected no events for target being deleted, got: %s", event)
	default:
	}
}

func TestConfigMapReplicatorReconciler_UpdateError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	sourceCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-bundle",
			Namespace: "garden",
			Annotations: map[string]string{
				replicator.AnnotationReplicatableFromNamespaces: "shoot-a",
			},
		},
		Data: map[string]string{"ca.crt": "cert-content"},
	}

	targetCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-bundle",
			Namespace: "shoot-a",
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: "garden/ca-bundle",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceCM, targetCM).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if cm, ok := obj.(*corev1.ConfigMap); ok && cm.Namespace == "shoot-a" {
					return fmt.Errorf("simulated update error")
				}
				return c.Update(ctx, obj, opts...)
			},
		}).
		Build()

	recorder := NewTestEventRecorder(10)
	reconciler := newConfigMapReconciler(fakeClient, scheme, config.NewDefaultConfig(), recorder)

	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(targetCM)}
	if _, err := reconciler.Reconcile(context.Background(), req); err == nil {
		t.Error("Expected error from Reconcile when update fails")
	}

	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "Warning") || !strings.Contains(event, "Failed to update") {
			t.Errorf("Expected warning event about failed update, got: %s", event)
		}
	default:
		t.Error("Expected a warning event for failed update")
	}
}

func TestConfigMapReplicatorReconciler_FindTargetsForSource(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	sourceCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-bundle",
			Namespace: "garden",
		},
	}

	target1 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-bundle",
			Namespace: "shoot-a",
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: "garden/ca-bundle",
			},
		},
	}

	target2 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-bundle",
			Namespace: "shoot-b",
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: "garden/ca-bundle",
			},
		},
	}

	unrelated := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other",
			Namespace: "shoot-a",
			Annotations: map[string]string{
				replicator.AnnotationReplicateFrom: "elsewhere/other",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sourceCM, target1, target2, unrelated).
		Build()

	reconciler := newConfigMapReconciler(fakeClient, scheme, config.NewDefaultConfig(), NewTestEventRecorder(10))

	requests := reconciler.findTargetsForSource(context.Background(), sourceCM)
	if len(requests) != 2 {
		t.Fatalf("Expected 2 reconcile requests, got %d", len(requests))
	}

	found := map[string]bool{}
	for _, req := range requests {
		found[req.Namespace] = true
	}
	if !found["shoot-a"] || !found["shoot-b"] {
		t.Errorf("Expected requests for shoot-a and shoot-b, got %v", requests)
	}

	// Non-ConfigMap object returns nil
	if reqs := reconciler.findTargetsForSource(context.Background(), &corev1.Secret{}); reqs != nil {
		t.Error("Expected nil requests for non-ConfigMap object")
	}
}
