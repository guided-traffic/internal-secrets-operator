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
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/guided-traffic/k8s-secret-operator/pkg/generator"
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
		DefaultLength: 32,
		DefaultType:   "string",
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
		DefaultLength: 32,
		DefaultType:   "string",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.secret).
				Build()

			gen := generator.NewSecretGenerator()

			reconciler := &SecretReconciler{
				Client:        fakeClient,
				Scheme:        scheme,
				Generator:     gen,
				DefaultLength: 32,
				DefaultType:   "string",
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
				if updatedSecret.Annotations[AnnotationSecure] != "yes" {
					t.Error("expected secure annotation to be set to 'yes'")
				}

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

	reconciler := &SecretReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Generator:     gen,
		DefaultLength: 32,
		DefaultType:   "string",
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
