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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/guided-traffic/internal-secrets-operator/pkg/config"
	"github.com/guided-traffic/internal-secrets-operator/pkg/generator"
)

func TestParseFields(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "single field",
			input:    "password",
			expected: []string{"password"},
		},
		{
			name:     "multiple fields",
			input:    "password,api-key,token",
			expected: []string{"password", "api-key", "token"},
		},
		{
			name:     "fields with spaces",
			input:    "password, api-key , token",
			expected: []string{"password", "api-key", "token"},
		},
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "only commas",
			input:    ",,,",
			expected: nil,
		},
		{
			name:     "trailing comma",
			input:    "password,",
			expected: []string{"password"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseFields(tt.input)

			if len(result) != len(tt.expected) {
				t.Errorf("expected %d fields, got %d", len(tt.expected), len(result))
				return
			}

			for i, field := range result {
				if field != tt.expected[i] {
					t.Errorf("expected field %d to be %q, got %q", i, tt.expected[i], field)
				}
			}
		})
	}
}

func TestGetAnnotationOrDefault(t *testing.T) {
	r := &SecretReconciler{
		Config: config.NewDefaultConfig(),
	}

	tests := []struct {
		name         string
		annotations  map[string]string
		key          string
		defaultValue string
		expected     string
	}{
		{
			name:         "annotation exists",
			annotations:  map[string]string{"key": "value"},
			key:          "key",
			defaultValue: "default",
			expected:     "value",
		},
		{
			name:         "annotation missing",
			annotations:  map[string]string{},
			key:          "key",
			defaultValue: "default",
			expected:     "default",
		},
		{
			name:         "annotation empty",
			annotations:  map[string]string{"key": ""},
			key:          "key",
			defaultValue: "default",
			expected:     "default",
		},
		{
			name:         "nil annotations",
			annotations:  nil,
			key:          "key",
			defaultValue: "default",
			expected:     "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.getAnnotationOrDefault(tt.annotations, tt.key, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestGetLengthAnnotation(t *testing.T) {
	r := &SecretReconciler{
		Config: config.NewDefaultConfig(),
	}

	tests := []struct {
		name        string
		annotations map[string]string
		expected    int
	}{
		{
			name:        "valid length",
			annotations: map[string]string{AnnotationLength: "64"},
			expected:    64,
		},
		{
			name:        "invalid length",
			annotations: map[string]string{AnnotationLength: "invalid"},
			expected:    32,
		},
		{
			name:        "negative length",
			annotations: map[string]string{AnnotationLength: "-1"},
			expected:    32,
		},
		{
			name:        "zero length",
			annotations: map[string]string{AnnotationLength: "0"},
			expected:    32,
		},
		{
			name:        "missing annotation",
			annotations: map[string]string{},
			expected:    32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.getLengthAnnotation(tt.annotations)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestGetFieldType(t *testing.T) {
	r := &SecretReconciler{
		Config: config.NewDefaultConfig(),
	}

	tests := []struct {
		name        string
		annotations map[string]string
		field       string
		expected    string
	}{
		{
			name:        "field-specific type",
			annotations: map[string]string{AnnotationTypePrefix + "encryption-key": "bytes"},
			field:       "encryption-key",
			expected:    "bytes",
		},
		{
			name: "field-specific overrides default",
			annotations: map[string]string{
				AnnotationType:                          "string",
				AnnotationTypePrefix + "encryption-key": "bytes",
			},
			field:    "encryption-key",
			expected: "bytes",
		},
		{
			name:        "fallback to default type annotation",
			annotations: map[string]string{AnnotationType: "bytes"},
			field:       "password",
			expected:    "bytes",
		},
		{
			name:        "fallback to reconciler default",
			annotations: map[string]string{},
			field:       "password",
			expected:    "string",
		},
		{
			name: "different field uses default",
			annotations: map[string]string{
				AnnotationTypePrefix + "encryption-key": "bytes",
				AnnotationType:                          "string",
			},
			field:    "password",
			expected: "string",
		},
		{
			name:        "nil annotations",
			annotations: nil,
			field:       "password",
			expected:    "string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.getFieldType(tt.annotations, tt.field)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestGetFieldLength(t *testing.T) {
	r := &SecretReconciler{
		Config: config.NewDefaultConfig(),
	}

	tests := []struct {
		name        string
		annotations map[string]string
		field       string
		expected    int
	}{
		{
			name:        "field-specific length",
			annotations: map[string]string{AnnotationLengthPrefix + "encryption-key": "64"},
			field:       "encryption-key",
			expected:    64,
		},
		{
			name: "field-specific overrides default",
			annotations: map[string]string{
				AnnotationLength: "24",
				AnnotationLengthPrefix + "encryption-key": "64",
			},
			field:    "encryption-key",
			expected: 64,
		},
		{
			name:        "fallback to default length annotation",
			annotations: map[string]string{AnnotationLength: "48"},
			field:       "password",
			expected:    48,
		},
		{
			name:        "fallback to reconciler default",
			annotations: map[string]string{},
			field:       "password",
			expected:    32,
		},
		{
			name: "different field uses default",
			annotations: map[string]string{
				AnnotationLengthPrefix + "encryption-key": "64",
				AnnotationLength: "24",
			},
			field:    "password",
			expected: 24,
		},
		{
			name:        "invalid field-specific length falls back",
			annotations: map[string]string{AnnotationLengthPrefix + "password": "invalid"},
			field:       "password",
			expected:    32,
		},
		{
			name: "invalid field-specific uses default annotation",
			annotations: map[string]string{
				AnnotationLengthPrefix + "password": "invalid",
				AnnotationLength:                    "48",
			},
			field:    "password",
			expected: 48,
		},
		{
			name:        "zero field-specific length falls back",
			annotations: map[string]string{AnnotationLengthPrefix + "password": "0"},
			field:       "password",
			expected:    32,
		},
		{
			name:        "negative field-specific length falls back",
			annotations: map[string]string{AnnotationLengthPrefix + "password": "-1"},
			field:       "password",
			expected:    32,
		},
		{
			name:        "nil annotations",
			annotations: nil,
			field:       "password",
			expected:    32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.getFieldLength(tt.annotations, tt.field)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestReconcile(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	tests := []struct {
		name           string
		secret         *corev1.Secret
		expectGenerate bool
		expectFields   []string
	}{
		{
			name: "secret with autogenerate annotation",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "default",
					Annotations: map[string]string{
						AnnotationAutogenerate: "password",
					},
				},
				Data: map[string][]byte{
					"username": []byte("dXNlcg=="), // "user" base64 encoded
				},
			},
			expectGenerate: true,
			expectFields:   []string{"password"},
		},
		{
			name: "secret without autogenerate annotation",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"username": []byte("dXNlcg=="),
				},
			},
			expectGenerate: false,
			expectFields:   nil,
		},
		{
			name: "secret with existing field value",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "default",
					Annotations: map[string]string{
						AnnotationAutogenerate: "password",
					},
				},
				Data: map[string][]byte{
					"password": []byte("ZXhpc3Rpbmc="), // "existing" base64 encoded
				},
			},
			expectGenerate: false, // Should not overwrite existing values
			expectFields:   nil,
		},
		{
			name: "secret with field-specific type and length",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "default",
					Annotations: map[string]string{
						AnnotationAutogenerate:                    "password,encryption-key",
						AnnotationType:                            "string",
						AnnotationLength:                          "24",
						AnnotationTypePrefix + "encryption-key":   "bytes",
						AnnotationLengthPrefix + "encryption-key": "32",
					},
				},
			},
			expectGenerate: true,
			expectFields:   []string{"password", "encryption-key"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.secret).
				Build()

			gen := generator.NewSecretGenerator()
			fakeRecorder := record.NewFakeRecorder(10)

			reconciler := &SecretReconciler{
				Client:        fakeClient,
				Scheme:        scheme,
				Generator:     gen,
				Config:        config.NewDefaultConfig(),
				EventRecorder: fakeRecorder,
			}

			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      tt.secret.Name,
					Namespace: tt.secret.Namespace,
				},
			}

			_, err := reconciler.Reconcile(context.Background(), req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Fetch the updated secret
			var updatedSecret corev1.Secret
			err = fakeClient.Get(context.Background(), req.NamespacedName, &updatedSecret)
			if err != nil {
				t.Fatalf("failed to get secret: %v", err)
			}

			if tt.expectGenerate {
				// Verify the expected fields were generated
				for _, field := range tt.expectFields {
					if _, ok := updatedSecret.Data[field]; !ok {
						t.Errorf("expected field %q to be generated", field)
					}
				}

				// Verify metadata annotations were added
				if _, ok := updatedSecret.Annotations[AnnotationGeneratedAt]; !ok {
					t.Error("expected generated-at annotation to be set")
				}
			}
		})
	}
}

func TestReconcileSecretNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := record.NewFakeRecorder(10)

	reconciler := &SecretReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Generator:     gen,
		Config:        config.NewDefaultConfig(),
		EventRecorder: fakeRecorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "nonexistent",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should return empty result without error for not found
	if result.RequeueAfter != time.Duration(0) {
		t.Error("expected empty result for not found secret")
	}
}

func TestReconcileEmitsSuccessEvent(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := record.NewFakeRecorder(10)

	reconciler := &SecretReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Generator:     gen,
		Config:        config.NewDefaultConfig(),
		EventRecorder: fakeRecorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      secret.Name,
			Namespace: secret.Namespace,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that a success event was emitted
	select {
	case event := <-fakeRecorder.Events:
		expectedPrefix := fmt.Sprintf("%s %s", corev1.EventTypeNormal, EventReasonGenerationSucceeded)
		if len(event) < len(expectedPrefix) || event[:len(expectedPrefix)] != expectedPrefix {
			t.Errorf("expected event to start with %q, got %q", expectedPrefix, event)
		}
	default:
		t.Error("expected a success event to be emitted")
	}
}

func TestReconcileEmitsWarningEventOnError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
				AnnotationType:         "invalid-type", // Invalid type should cause error
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := record.NewFakeRecorder(10)

	reconciler := &SecretReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Generator:     gen,
		Config:        config.NewDefaultConfig(),
		EventRecorder: fakeRecorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      secret.Name,
			Namespace: secret.Namespace,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Fatal("expected an error for invalid type")
	}

	// Check that a warning event was emitted
	select {
	case event := <-fakeRecorder.Events:
		expectedPrefix := fmt.Sprintf("%s %s", corev1.EventTypeWarning, EventReasonGenerationFailed)
		if len(event) < len(expectedPrefix) || event[:len(expectedPrefix)] != expectedPrefix {
			t.Errorf("expected event to start with %q, got %q", expectedPrefix, event)
		}
	default:
		t.Error("expected a warning event to be emitted")
	}
}

func TestReconcileNoEventWhenNoChanges(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// Secret with existing value - no generation needed
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
			},
		},
		Data: map[string][]byte{
			"password": []byte("existing-value"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := record.NewFakeRecorder(10)

	reconciler := &SecretReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Generator:     gen,
		Config:        config.NewDefaultConfig(),
		EventRecorder: fakeRecorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      secret.Name,
			Namespace: secret.Namespace,
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that no event was emitted (field already has value)
	select {
	case event := <-fakeRecorder.Events:
		t.Errorf("expected no event to be emitted, got %q", event)
	default:
		// No event - expected behavior
	}
}
