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
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/guided-traffic/internal-secrets-operator/pkg/config"
	"github.com/guided-traffic/internal-secrets-operator/pkg/generator"
)

// MockClock is a mock implementation of Clock for testing
type MockClock struct {
	currentTime time.Time
}

// Now returns the mocked current time
func (m *MockClock) Now() time.Time {
	return m.currentTime
}

// TestEventRecorder is a simple mock for events.EventRecorder used in tests
type TestEventRecorder struct {
	Events chan string
}

// Eventf records an event with formatted message (implements events.EventRecorder)
func (t *TestEventRecorder) Eventf(regarding runtime.Object, related runtime.Object, eventtype, reason, action, note string, args ...interface{}) {
	msg := fmt.Sprintf(note, args...)
	event := fmt.Sprintf("%s %s: %s", eventtype, reason, msg)
	select {
	case t.Events <- event:
	default:
		// Channel full, drop event
	}
}

// NewTestEventRecorder creates a new TestEventRecorder for testing
func NewTestEventRecorder(bufferSize int) *TestEventRecorder {
	return &TestEventRecorder{
		Events: make(chan string, bufferSize),
	}
}

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
			fakeRecorder := NewTestEventRecorder(10)

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
	fakeRecorder := NewTestEventRecorder(10)

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
	fakeRecorder := NewTestEventRecorder(10)

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
	fakeRecorder := NewTestEventRecorder(10)

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
	fakeRecorder := NewTestEventRecorder(10)

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

func TestGetFieldRotationInterval(t *testing.T) {
	r := &SecretReconciler{
		Config: config.NewDefaultConfig(),
	}

	tests := []struct {
		name        string
		annotations map[string]string
		field       string
		expected    time.Duration
	}{
		{
			name:        "no rotation configured",
			annotations: map[string]string{},
			field:       "password",
			expected:    0,
		},
		{
			name:        "default rotation",
			annotations: map[string]string{AnnotationRotate: "24h"},
			field:       "password",
			expected:    24 * time.Hour,
		},
		{
			name:        "field-specific rotation",
			annotations: map[string]string{AnnotationRotatePrefix + "password": "7d"},
			field:       "password",
			expected:    7 * 24 * time.Hour,
		},
		{
			name: "field-specific overrides default",
			annotations: map[string]string{
				AnnotationRotate:                   "24h",
				AnnotationRotatePrefix + "api-key": "30d",
			},
			field:    "api-key",
			expected: 30 * 24 * time.Hour,
		},
		{
			name: "different field uses default",
			annotations: map[string]string{
				AnnotationRotate:                   "24h",
				AnnotationRotatePrefix + "api-key": "30d",
			},
			field:    "password",
			expected: 24 * time.Hour,
		},
		{
			name:        "invalid rotation format returns 0",
			annotations: map[string]string{AnnotationRotate: "invalid"},
			field:       "password",
			expected:    0,
		},
		{
			name: "invalid field-specific falls back to default",
			annotations: map[string]string{
				AnnotationRotate:                      "24h",
				AnnotationRotatePrefix + "encryption": "invalid",
			},
			field:    "encryption",
			expected: 24 * time.Hour,
		},
		{
			name:        "rotation with minutes",
			annotations: map[string]string{AnnotationRotate: "30m"},
			field:       "password",
			expected:    30 * time.Minute,
		},
		{
			name:        "nil annotations",
			annotations: nil,
			field:       "password",
			expected:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.getFieldRotationInterval(tt.annotations, tt.field)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGetGeneratedAtTime(t *testing.T) {
	r := &SecretReconciler{
		Config: config.NewDefaultConfig(),
	}

	now := time.Now()
	nowStr := now.Format(time.RFC3339)

	tests := []struct {
		name        string
		annotations map[string]string
		expectNil   bool
	}{
		{
			name:        "no generated-at annotation",
			annotations: map[string]string{},
			expectNil:   true,
		},
		{
			name:        "valid generated-at annotation",
			annotations: map[string]string{AnnotationGeneratedAt: nowStr},
			expectNil:   false,
		},
		{
			name:        "invalid generated-at annotation",
			annotations: map[string]string{AnnotationGeneratedAt: "invalid"},
			expectNil:   true,
		},
		{
			name:        "empty generated-at annotation",
			annotations: map[string]string{AnnotationGeneratedAt: ""},
			expectNil:   true,
		},
		{
			name:        "nil annotations",
			annotations: nil,
			expectNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.getGeneratedAtTime(tt.annotations)
			if tt.expectNil && result != nil {
				t.Errorf("expected nil, got %v", result)
			}
			if !tt.expectNil && result == nil {
				t.Error("expected non-nil result")
			}
		})
	}
}

func TestReconcileWithRotation(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// Create a secret that was generated 2 hours ago with 1 hour rotation
	oldTime := time.Now().Add(-2 * time.Hour)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
				AnnotationRotate:       "1h",
				AnnotationGeneratedAt:  oldTime.Format(time.RFC3339),
			},
		},
		Data: map[string][]byte{
			"password": []byte("old-password"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

	cfg := config.NewDefaultConfig()
	cfg.Rotation.CreateEvents = true

	reconciler := &SecretReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Generator:     gen,
		Config:        cfg,
		EventRecorder: fakeRecorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      secret.Name,
			Namespace: secret.Namespace,
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Fetch the updated secret
	var updatedSecret corev1.Secret
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updatedSecret)
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}

	// Verify the password was rotated (different from old value)
	newPassword := string(updatedSecret.Data["password"])
	if newPassword == "old-password" {
		t.Error("expected password to be rotated")
	}

	// Verify generated-at timestamp was updated
	newGeneratedAt := updatedSecret.Annotations[AnnotationGeneratedAt]
	if newGeneratedAt == oldTime.Format(time.RFC3339) {
		t.Error("expected generated-at to be updated")
	}

	// Verify RequeueAfter is set for next rotation
	if result.RequeueAfter == 0 {
		t.Error("expected RequeueAfter to be set")
	}

	// Check for rotation event
	select {
	case event := <-fakeRecorder.Events:
		expectedPrefix := fmt.Sprintf("%s %s", corev1.EventTypeNormal, EventReasonRotationSucceeded)
		if len(event) < len(expectedPrefix) || event[:len(expectedPrefix)] != expectedPrefix {
			t.Errorf("expected event to start with %q, got %q", expectedPrefix, event)
		}
	default:
		t.Error("expected a rotation event to be emitted")
	}
}

func TestReconcileWithRotationNotYetDue(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// Create a secret that was generated 30 minutes ago with 1 hour rotation
	recentTime := time.Now().Add(-30 * time.Minute)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
				AnnotationRotate:       "1h",
				AnnotationGeneratedAt:  recentTime.Format(time.RFC3339),
			},
		},
		Data: map[string][]byte{
			"password": []byte("current-password"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

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

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Fetch the secret - should not be updated
	var updatedSecret corev1.Secret
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updatedSecret)
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}

	// Verify the password was NOT rotated
	if string(updatedSecret.Data["password"]) != "current-password" {
		t.Error("expected password to NOT be rotated")
	}

	// Verify RequeueAfter is set for when rotation is due (~30 minutes)
	if result.RequeueAfter == 0 {
		t.Error("expected RequeueAfter to be set")
	}
	if result.RequeueAfter > 35*time.Minute || result.RequeueAfter < 25*time.Minute {
		t.Errorf("expected RequeueAfter around 30 minutes, got %v", result.RequeueAfter)
	}

	// No events should be emitted
	select {
	case event := <-fakeRecorder.Events:
		t.Errorf("expected no events, got %q", event)
	default:
		// Expected - no events
	}
}

func TestReconcileRotationBelowMinInterval(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// Create a secret with rotation interval below minInterval (1m < 5m default)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
				AnnotationRotate:       "1m", // Below default minInterval of 5m
				AnnotationGeneratedAt:  time.Now().Add(-2 * time.Minute).Format(time.RFC3339),
			},
		},
		Data: map[string][]byte{
			"password": []byte("current-password"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

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

	// Fetch the secret - should not be updated (rotation skipped)
	var updatedSecret corev1.Secret
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updatedSecret)
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}

	// Verify the password was NOT rotated
	if string(updatedSecret.Data["password"]) != "current-password" {
		t.Error("expected password to NOT be rotated (interval below minInterval)")
	}

	// Check for warning event about invalid rotation interval
	select {
	case event := <-fakeRecorder.Events:
		expectedPrefix := fmt.Sprintf("%s %s", corev1.EventTypeWarning, EventReasonRotationFailed)
		if len(event) < len(expectedPrefix) || event[:len(expectedPrefix)] != expectedPrefix {
			t.Errorf("expected event to start with %q, got %q", expectedPrefix, event)
		}
	default:
		t.Error("expected a warning event about rotation interval")
	}
}

func TestReconcileWithFieldSpecificRotation(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// Create a secret with different rotation intervals per field
	// password: 1h rotation, needs rotation (generated 2h ago)
	// api-key: 24h rotation, does not need rotation
	oldTime := time.Now().Add(-2 * time.Hour)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate:              "password,api-key",
				AnnotationRotate:                    "24h",
				AnnotationRotatePrefix + "password": "1h",
				AnnotationGeneratedAt:               oldTime.Format(time.RFC3339),
			},
		},
		Data: map[string][]byte{
			"password": []byte("old-password"),
			"api-key":  []byte("old-api-key"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

	cfg := config.NewDefaultConfig()
	cfg.Rotation.CreateEvents = true

	reconciler := &SecretReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Generator:     gen,
		Config:        cfg,
		EventRecorder: fakeRecorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      secret.Name,
			Namespace: secret.Namespace,
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Fetch the updated secret
	var updatedSecret corev1.Secret
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updatedSecret)
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}

	// Verify the password was rotated
	if string(updatedSecret.Data["password"]) == "old-password" {
		t.Error("expected password to be rotated")
	}

	// Verify RequeueAfter is set for next rotation (should be ~1h for password)
	if result.RequeueAfter == 0 {
		t.Error("expected RequeueAfter to be set")
	}
}

func TestReconcileInitialGenerationWithBelowMinInterval(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// Create a NEW secret (no existing data) with rotation interval below minInterval
	// This tests that initial generation still works even if rotation config is invalid
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
				AnnotationRotate:       "1s", // Below minInterval of 5s (like E2E test)
			},
		},
		// No Data field - simulates a new secret
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

	// Use config with 5s minInterval (like E2E test)
	cfg := config.NewDefaultConfig()
	cfg.Rotation.MinInterval = config.Duration(5 * time.Second)

	reconciler := &SecretReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Generator:     gen,
		Config:        cfg,
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

	// Fetch the secret - should be updated with generated password
	var updatedSecret corev1.Secret
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updatedSecret)
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}

	// Verify the password WAS generated (initial generation should work despite invalid rotation)
	if _, ok := updatedSecret.Data["password"]; !ok {
		t.Error("expected password to be generated despite invalid rotation interval")
	}

	// Check for warning event about invalid rotation interval
	select {
	case event := <-fakeRecorder.Events:
		expectedPrefix := fmt.Sprintf("%s %s", corev1.EventTypeWarning, EventReasonRotationFailed)
		if len(event) < len(expectedPrefix) || event[:len(expectedPrefix)] != expectedPrefix {
			t.Errorf("expected event to start with %q, got %q", expectedPrefix, event)
		}
	default:
		t.Error("expected a warning event about rotation interval")
	}
}

func TestParseBoolAnnotation(t *testing.T) {
	tests := []struct {
		name          string
		annotations   map[string]string
		key           string
		expectedValue bool
		expectedOk    bool
	}{
		{
			name:          "true lowercase",
			annotations:   map[string]string{"key": "true"},
			key:           "key",
			expectedValue: true,
			expectedOk:    true,
		},
		{
			name:          "True uppercase",
			annotations:   map[string]string{"key": "True"},
			key:           "key",
			expectedValue: true,
			expectedOk:    true,
		},
		{
			name:          "TRUE all caps",
			annotations:   map[string]string{"key": "TRUE"},
			key:           "key",
			expectedValue: true,
			expectedOk:    true,
		},
		{
			name:          "1 as true",
			annotations:   map[string]string{"key": "1"},
			key:           "key",
			expectedValue: true,
			expectedOk:    true,
		},
		{
			name:          "false lowercase",
			annotations:   map[string]string{"key": "false"},
			key:           "key",
			expectedValue: false,
			expectedOk:    true,
		},
		{
			name:          "False uppercase",
			annotations:   map[string]string{"key": "False"},
			key:           "key",
			expectedValue: false,
			expectedOk:    true,
		},
		{
			name:          "0 as false",
			annotations:   map[string]string{"key": "0"},
			key:           "key",
			expectedValue: false,
			expectedOk:    true,
		},
		{
			name:          "missing key",
			annotations:   map[string]string{},
			key:           "key",
			expectedValue: false,
			expectedOk:    false,
		},
		{
			name:          "invalid value",
			annotations:   map[string]string{"key": "invalid"},
			key:           "key",
			expectedValue: false,
			expectedOk:    false,
		},
		{
			name:          "empty value",
			annotations:   map[string]string{"key": ""},
			key:           "key",
			expectedValue: false,
			expectedOk:    false,
		},
		{
			name:          "whitespace around true",
			annotations:   map[string]string{"key": "  true  "},
			key:           "key",
			expectedValue: true,
			expectedOk:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, ok := parseBoolAnnotation(tt.annotations, tt.key)
			if value != tt.expectedValue {
				t.Errorf("expected value %v, got %v", tt.expectedValue, value)
			}
			if ok != tt.expectedOk {
				t.Errorf("expected ok %v, got %v", tt.expectedOk, ok)
			}
		})
	}
}

func TestGetCharsetFromAnnotations(t *testing.T) {
	r := &SecretReconciler{
		Config: config.NewDefaultConfig(),
	}

	tests := []struct {
		name          string
		annotations   map[string]string
		expectError   bool
		expectCharset string
		description   string
	}{
		{
			name:          "use config defaults",
			annotations:   map[string]string{},
			expectError:   false,
			expectCharset: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
			description:   "should use config defaults (uppercase, lowercase, numbers, no special chars)",
		},
		{
			name: "enable special chars",
			annotations: map[string]string{
				AnnotationStringSpecialChars:        "true",
				AnnotationStringAllowedSpecialChars: "!@#$",
			},
			expectError:   false,
			expectCharset: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$",
			description:   "should include special chars when enabled",
		},
		{
			name: "only lowercase",
			annotations: map[string]string{
				AnnotationStringUppercase: "false",
				AnnotationStringNumbers:   "false",
			},
			expectError:   false,
			expectCharset: "abcdefghijklmnopqrstuvwxyz",
			description:   "should only include lowercase",
		},
		{
			name: "only uppercase",
			annotations: map[string]string{
				AnnotationStringLowercase: "false",
				AnnotationStringNumbers:   "false",
			},
			expectError:   false,
			expectCharset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			description:   "should only include uppercase",
		},
		{
			name: "only numbers",
			annotations: map[string]string{
				AnnotationStringUppercase: "false",
				AnnotationStringLowercase: "false",
			},
			expectError:   false,
			expectCharset: "0123456789",
			description:   "should only include numbers",
		},
		{
			name: "custom special chars",
			annotations: map[string]string{
				AnnotationStringSpecialChars:        "true",
				AnnotationStringAllowedSpecialChars: "!@#",
			},
			expectError:   false,
			expectCharset: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#",
			description:   "should use custom special chars",
		},
		{
			name: "no charset enabled",
			annotations: map[string]string{
				AnnotationStringUppercase: "false",
				AnnotationStringLowercase: "false",
				AnnotationStringNumbers:   "false",
			},
			expectError: true,
			description: "should error when no charset options enabled",
		},
		{
			name: "special chars enabled but empty",
			annotations: map[string]string{
				AnnotationStringSpecialChars:        "true",
				AnnotationStringAllowedSpecialChars: "",
			},
			expectError: true,
			description: "should error when special chars enabled but empty",
		},
		{
			name: "override config with all false except numbers",
			annotations: map[string]string{
				AnnotationStringUppercase: "0",
				AnnotationStringLowercase: "0",
				AnnotationStringNumbers:   "1",
			},
			expectError:   false,
			expectCharset: "0123456789",
			description:   "should handle 0/1 as bool values",
		},
		{
			name: "lowercase and special chars only",
			annotations: map[string]string{
				AnnotationStringUppercase:           "false",
				AnnotationStringNumbers:             "false",
				AnnotationStringSpecialChars:        "true",
				AnnotationStringAllowedSpecialChars: "_-.",
			},
			expectError:   false,
			expectCharset: "abcdefghijklmnopqrstuvwxyz_-.",
			description:   "should combine lowercase and special chars",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			charset, err := r.getCharsetFromAnnotations(tt.annotations)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none: %s", tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v (%s)", err, tt.description)
				}
				if charset != tt.expectCharset {
					t.Errorf("expected charset %q, got %q (%s)", tt.expectCharset, charset, tt.description)
				}
			}
		})
	}
}

func TestReconcileWithCustomCharset(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	tests := []struct {
		name        string
		annotations map[string]string
		expectError bool
		checkValue  func(t *testing.T, value []byte)
	}{
		{
			name: "generate with uppercase only",
			annotations: map[string]string{
				AnnotationAutogenerate:    "password",
				AnnotationStringLowercase: "false",
				AnnotationStringNumbers:   "false",
			},
			expectError: false,
			checkValue: func(t *testing.T, value []byte) {
				for _, b := range value {
					if b < 'A' || b > 'Z' {
						t.Errorf("expected only uppercase letters, got byte %c", b)
					}
				}
			},
		},
		{
			name: "generate with numbers only",
			annotations: map[string]string{
				AnnotationAutogenerate:    "password",
				AnnotationStringUppercase: "false",
				AnnotationStringLowercase: "false",
			},
			expectError: false,
			checkValue: func(t *testing.T, value []byte) {
				for _, b := range value {
					if b < '0' || b > '9' {
						t.Errorf("expected only numbers, got byte %c", b)
					}
				}
			},
		},
		{
			name: "generate with special chars",
			annotations: map[string]string{
				AnnotationAutogenerate:              "password",
				AnnotationStringSpecialChars:        "true",
				AnnotationStringAllowedSpecialChars: "!@#",
				AnnotationLength:                    "100", // Larger to ensure special chars appear
			},
			expectError: false,
			checkValue: func(t *testing.T, value []byte) {
				// With 100 chars, at least one should be a special char (statistically)
				hasSpecial := false
				for _, b := range value {
					if b == '!' || b == '@' || b == '#' {
						hasSpecial = true
						break
					}
				}
				// Note: This is probabilistic, but with 100 chars it's very unlikely to fail
				if !hasSpecial {
					t.Log("Warning: no special chars in generated value (unlikely but possible)")
				}
			},
		},
		{
			name: "fail with no charset enabled",
			annotations: map[string]string{
				AnnotationAutogenerate:    "password",
				AnnotationStringUppercase: "false",
				AnnotationStringLowercase: "false",
				AnnotationStringNumbers:   "false",
			},
			expectError: true,
		},
		{
			name: "fail with special chars but empty allowedSpecialChars",
			annotations: map[string]string{
				AnnotationAutogenerate:              "password",
				AnnotationStringSpecialChars:        "true",
				AnnotationStringAllowedSpecialChars: "",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-secret",
					Namespace:   "default",
					Annotations: tt.annotations,
				},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(secret).
				Build()

			gen := generator.NewSecretGenerator()
			fakeRecorder := NewTestEventRecorder(10)
			cfg := config.NewDefaultConfig()

			reconciler := &SecretReconciler{
				Client:        fakeClient,
				Scheme:        scheme,
				Generator:     gen,
				Config:        cfg,
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
				t.Fatalf("unexpected error from Reconcile: %v", err)
			}

			// Fetch the updated secret
			var updatedSecret corev1.Secret
			err = fakeClient.Get(context.Background(), req.NamespacedName, &updatedSecret)
			if err != nil {
				t.Fatalf("failed to get secret: %v", err)
			}

			if tt.expectError {
				// Should have a warning event
				select {
				case event := <-fakeRecorder.Events:
					if event[:len(corev1.EventTypeWarning)] != corev1.EventTypeWarning {
						t.Errorf("expected warning event, got: %s", event)
					}
				default:
					t.Error("expected a warning event")
				}

				// Should not have generated a value
				if _, ok := updatedSecret.Data["password"]; ok {
					t.Error("expected no password to be generated")
				}
			} else {
				// Should have generated a value
				if value, ok := updatedSecret.Data["password"]; !ok {
					t.Error("expected password to be generated")
				} else if tt.checkValue != nil {
					tt.checkValue(t, value)
				}

				// Should have a success event
				select {
				case event := <-fakeRecorder.Events:
					expectedPrefix := fmt.Sprintf("%s %s", corev1.EventTypeNormal, EventReasonGenerationSucceeded)
					if len(event) < len(expectedPrefix) || event[:len(expectedPrefix)] != expectedPrefix {
						t.Errorf("expected success event, got: %s", event)
					}
				default:
					t.Error("expected a success event")
				}
			}
		})
	}
}

func TestReconcilerNowWithoutClock(t *testing.T) {
	// Test that now() works without Clock set (uses time.Now())
	reconciler := &SecretReconciler{
		Config: config.NewDefaultConfig(),
		Clock:  nil, // No clock set
	}

	before := time.Now()
	result := reconciler.now()
	after := time.Now()

	if result.Before(before) || result.After(after) {
		t.Errorf("expected now() to return a time between %v and %v, got %v", before, after, result)
	}
}

func TestCalculateNextRotationWithJustRotatedField(t *testing.T) {
	// This tests the path where rotationCheck.timeUntilRotation is nil
	// but rotationCheck.rotationInterval > 0 (field was just rotated)
	cfg := config.NewDefaultConfig()
	cfg.Rotation.MinInterval = config.Duration(1 * time.Minute)

	reconciler := &SecretReconciler{
		Config: cfg,
	}

	// Set generatedAt to now (just generated), so there's no timeUntilRotation
	now := time.Now()
	annotations := map[string]string{
		AnnotationRotate: "10m",
	}
	fields := []string{"password"}

	// When generatedAt is very recent, rotation is needed so timeUntilRotation is nil
	// but we calculate based on rotationInterval
	nextRotation := reconciler.calculateNextRotation(annotations, fields, &now)

	if nextRotation == nil {
		t.Error("expected nextRotation to be non-nil")
		return
	}

	// Should be approximately 10 minutes
	expected := 10 * time.Minute
	tolerance := 1 * time.Second
	diff := *nextRotation - expected
	if diff < -tolerance || diff > tolerance {
		t.Errorf("expected nextRotation ~%v, got %v", expected, *nextRotation)
	}
}

func TestCalculateNextRotationWithMultipleFieldsDifferentIntervals(t *testing.T) {
	cfg := config.NewDefaultConfig()
	cfg.Rotation.MinInterval = config.Duration(1 * time.Minute)

	reconciler := &SecretReconciler{
		Config: cfg,
	}

	// Generated 5 minutes ago
	generatedAt := time.Now().Add(-5 * time.Minute)
	annotations := map[string]string{
		AnnotationRotatePrefix + "password": "10m", // 5 min until rotation
		AnnotationRotatePrefix + "token":    "15m", // 10 min until rotation
	}
	fields := []string{"password", "token"}

	nextRotation := reconciler.calculateNextRotation(annotations, fields, &generatedAt)

	if nextRotation == nil {
		t.Error("expected nextRotation to be non-nil")
		return
	}

	// Should pick the minimum: 5 minutes (for password)
	expected := 5 * time.Minute
	tolerance := 1 * time.Second
	diff := *nextRotation - expected
	if diff < -tolerance || diff > tolerance {
		t.Errorf("expected nextRotation ~%v, got %v", expected, *nextRotation)
	}
}

func TestCalculateNextRotationSkipsFieldsWithErrors(t *testing.T) {
	cfg := config.NewDefaultConfig()
	cfg.Rotation.MinInterval = config.Duration(10 * time.Minute) // Higher than some fields

	reconciler := &SecretReconciler{
		Config: cfg,
	}

	generatedAt := time.Now().Add(-5 * time.Minute)
	annotations := map[string]string{
		AnnotationRotatePrefix + "password": "5m",  // Invalid: below minInterval
		AnnotationRotatePrefix + "token":    "15m", // Valid: 10 min until rotation
	}
	fields := []string{"password", "token"}

	nextRotation := reconciler.calculateNextRotation(annotations, fields, &generatedAt)

	if nextRotation == nil {
		t.Error("expected nextRotation to be non-nil")
		return
	}

	// Should only consider the valid field (token): 10 min until rotation
	expected := 10 * time.Minute
	tolerance := 1 * time.Second
	diff := *nextRotation - expected
	if diff < -tolerance || diff > tolerance {
		t.Errorf("expected nextRotation ~%v, got %v", expected, *nextRotation)
	}
}

func TestReconcilerWithNilGeneratedAt(t *testing.T) {
	// Test checkFieldRotation with nil generatedAt but valid rotation interval
	cfg := config.NewDefaultConfig()
	cfg.Rotation.MinInterval = config.Duration(1 * time.Minute)

	reconciler := &SecretReconciler{
		Config: cfg,
	}

	annotations := map[string]string{
		AnnotationRotate: "10m",
	}

	result := reconciler.checkFieldRotation(annotations, "password", nil)

	// With nil generatedAt, timeUntilRotation should be set to rotationInterval
	if result.timeUntilRotation == nil {
		t.Error("expected timeUntilRotation to be non-nil")
		return
	}

	if *result.timeUntilRotation != 10*time.Minute {
		t.Errorf("expected timeUntilRotation to be 10m, got %v", *result.timeUntilRotation)
	}
}

func TestUpdateSecretAndEmitEventsUpdateError(t *testing.T) {
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

	// Create a client that will fail on Update
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				return fmt.Errorf("simulated update error")
			},
		}).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

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

	// Reconcile should return error when Update fails
	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Expected error from Reconcile when Update fails")
	}
}

func TestReconcileGetError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
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

	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

	reconciler := &SecretReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Generator:     gen,
		Config:        config.NewDefaultConfig(),
		EventRecorder: fakeRecorder,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "any-secret",
			Namespace: "default",
		},
	}

	// Reconcile should return error when Get fails (not NotFound)
	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Expected error from Reconcile when Get fails (not NotFound)")
	}
}

func TestReconcileRotationWithCreateEventsEnabled(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// Create a MockClock to control time
	fixedTime := time.Date(2025, 12, 6, 12, 0, 0, 0, time.UTC)
	mockClock := &MockClock{currentTime: fixedTime}

	// Secret that was generated 15 minutes ago with 10 minute rotation
	generatedAt := fixedTime.Add(-15 * time.Minute)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
				AnnotationRotate:       "10m",
				AnnotationGeneratedAt:  generatedAt.Format(time.RFC3339),
			},
		},
		Data: map[string][]byte{
			"password": []byte("old-value"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)
	cfg := config.NewDefaultConfig()
	cfg.Rotation.MinInterval = config.Duration(1 * time.Minute)
	cfg.Rotation.CreateEvents = true // Enable rotation events

	reconciler := &SecretReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Generator:     gen,
		Config:        cfg,
		EventRecorder: fakeRecorder,
		Clock:         mockClock,
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

	// Check that a rotation success event was emitted
	select {
	case event := <-fakeRecorder.Events:
		if !strings.Contains(event, EventReasonRotationSucceeded) {
			t.Errorf("expected rotation success event, got: %s", event)
		}
	default:
		t.Error("expected a rotation success event to be emitted")
	}
}

func TestReconcileRotationWithCreateEventsDisabled(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// Create a MockClock to control time
	fixedTime := time.Date(2025, 12, 6, 12, 0, 0, 0, time.UTC)
	mockClock := &MockClock{currentTime: fixedTime}

	// Secret that was generated 15 minutes ago with 10 minute rotation
	generatedAt := fixedTime.Add(-15 * time.Minute)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
				AnnotationRotate:       "10m",
				AnnotationGeneratedAt:  generatedAt.Format(time.RFC3339),
			},
		},
		Data: map[string][]byte{
			"password": []byte("old-value"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)
	cfg := config.NewDefaultConfig()
	cfg.Rotation.MinInterval = config.Duration(1 * time.Minute)
	cfg.Rotation.CreateEvents = false // Disable rotation events (default)

	reconciler := &SecretReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Generator:     gen,
		Config:        cfg,
		EventRecorder: fakeRecorder,
		Clock:         mockClock,
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

	// Check that NO rotation event was emitted (CreateEvents is false)
	select {
	case event := <-fakeRecorder.Events:
		if strings.Contains(event, EventReasonRotationSucceeded) {
			t.Errorf("expected no rotation event when CreateEvents is false, got: %s", event)
		}
	default:
		// No event is expected - this is correct
	}
}

func TestCalculateNextRotationWithJustRotatedFieldAndExisting(t *testing.T) {
	// Tests the path where both timeUntilRotation and rotationInterval are calculated
	// for multiple fields and the minimum is selected
	cfg := config.NewDefaultConfig()
	cfg.Rotation.MinInterval = config.Duration(1 * time.Minute)

	reconciler := &SecretReconciler{
		Config: cfg,
	}

	// generatedAt very recent (just rotated)
	generatedAt := time.Now()

	annotations := map[string]string{
		AnnotationRotatePrefix + "password": "5m",  // Just rotated, next in 5 min
		AnnotationRotatePrefix + "token":    "10m", // Just rotated, next in 10 min
	}
	fields := []string{"password", "token"}

	nextRotation := reconciler.calculateNextRotation(annotations, fields, &generatedAt)

	if nextRotation == nil {
		t.Error("expected nextRotation to be non-nil")
		return
	}

	// Should select the minimum: 5 min (for password)
	expected := 5 * time.Minute
	tolerance := 1 * time.Second
	diff := *nextRotation - expected
	if diff < -tolerance || diff > tolerance {
		t.Errorf("expected nextRotation ~%v, got %v", expected, *nextRotation)
	}
}

func TestCalculateNextRotationNoFieldsWithRotation(t *testing.T) {
	cfg := config.NewDefaultConfig()

	reconciler := &SecretReconciler{
		Config: cfg,
	}

	generatedAt := time.Now()

	// No rotation annotations
	annotations := map[string]string{}
	fields := []string{"password", "token"}

	nextRotation := reconciler.calculateNextRotation(annotations, fields, &generatedAt)

	// Should return nil when no fields have rotation configured
	if nextRotation != nil {
		t.Errorf("expected nil nextRotation when no rotation configured, got %v", *nextRotation)
	}
}

func TestReconcileWithNilSecretAnnotations(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// Secret with nil annotations
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			// Annotations intentionally nil
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

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

	// Should handle nil annotations gracefully
	_, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReconcileWithNilSecretData(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// Secret with nil Data
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
			},
		},
		// Data intentionally nil
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

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

	// Should initialize Data map and generate value
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

	// Should have generated a password
	if _, ok := updatedSecret.Data["password"]; !ok {
		t.Error("expected password to be generated")
	}
}

func TestSinceMethod(t *testing.T) {
	// Test the since method
	fixedTime := time.Date(2025, 12, 6, 12, 0, 0, 0, time.UTC)
	mockClock := &MockClock{currentTime: fixedTime}

	reconciler := &SecretReconciler{
		Config: config.NewDefaultConfig(),
		Clock:  mockClock,
	}

	pastTime := fixedTime.Add(-10 * time.Minute)
	elapsed := reconciler.since(pastTime)

	expected := 10 * time.Minute
	if elapsed != expected {
		t.Errorf("expected since to return %v, got %v", expected, elapsed)
	}
}

// TestMaintenanceWindowRotationDeferred tests that rotation is deferred when outside maintenance window
func TestMaintenanceWindowRotationDeferred(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)

	// Secret was generated 2 hours ago, rotation interval is 1 hour
	generatedAt := time.Date(2026, 2, 2, 10, 0, 0, 0, time.UTC) // Monday 10:00 UTC

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
				AnnotationRotate:       "1h",
				AnnotationGeneratedAt:  generatedAt.Format(time.RFC3339),
			},
		},
		Data: map[string][]byte{
			"password": []byte("old-password"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

	// Current time is Monday 12:00 UTC - rotation is due but we're outside maintenance window
	fixedTime := time.Date(2026, 2, 2, 12, 0, 0, 0, time.UTC)
	mockClock := &MockClock{currentTime: fixedTime}

	cfg := config.NewDefaultConfig()
	cfg.Rotation.MaintenanceWindows = config.MaintenanceWindowsConfig{
		Enabled: true,
		Windows: []config.MaintenanceWindow{
			{
				Name:      "weekend-night",
				Days:      []string{"saturday", "sunday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "UTC",
			},
		},
	}

	reconciler := &SecretReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Generator:     gen,
		Config:        cfg,
		EventRecorder: fakeRecorder,
		Clock:         mockClock,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      secret.Name,
			Namespace: secret.Namespace,
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have RequeueAfter set to next maintenance window
	if result.RequeueAfter == 0 {
		t.Error("expected RequeueAfter to be set for deferred rotation")
	}

	// Fetch the secret - password should NOT have changed
	var updatedSecret corev1.Secret
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updatedSecret)
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}

	if string(updatedSecret.Data["password"]) != "old-password" {
		t.Error("expected password to remain unchanged when rotation is deferred")
	}

	// Check for deferred rotation event
	select {
	case event := <-fakeRecorder.Events:
		if !strings.Contains(event, EventReasonRotationDeferred) {
			t.Errorf("expected deferred rotation event, got: %s", event)
		}
	default:
		t.Error("expected deferred rotation event to be recorded")
	}
}

// TestMaintenanceWindowRotationAllowed tests that rotation proceeds when inside maintenance window
func TestMaintenanceWindowRotationAllowed(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)

	// Secret was generated 2 hours ago, rotation interval is 1 hour
	generatedAt := time.Date(2026, 2, 7, 1, 0, 0, 0, time.UTC) // Saturday 01:00 UTC

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
				AnnotationRotate:       "1h",
				AnnotationGeneratedAt:  generatedAt.Format(time.RFC3339),
			},
		},
		Data: map[string][]byte{
			"password": []byte("old-password"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

	// Current time is Saturday 04:00 UTC - inside maintenance window, rotation is due
	fixedTime := time.Date(2026, 2, 7, 4, 0, 0, 0, time.UTC)
	mockClock := &MockClock{currentTime: fixedTime}

	cfg := config.NewDefaultConfig()
	cfg.Rotation.MaintenanceWindows = config.MaintenanceWindowsConfig{
		Enabled: true,
		Windows: []config.MaintenanceWindow{
			{
				Name:      "weekend-night",
				Days:      []string{"saturday", "sunday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "UTC",
			},
		},
	}

	reconciler := &SecretReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Generator:     gen,
		Config:        cfg,
		EventRecorder: fakeRecorder,
		Clock:         mockClock,
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

	// Fetch the secret - password should have changed
	var updatedSecret corev1.Secret
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updatedSecret)
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}

	if string(updatedSecret.Data["password"]) == "old-password" {
		t.Error("expected password to be rotated when inside maintenance window")
	}
}

// TestMaintenanceWindowDisabledAllowsRotation tests that rotation proceeds when maintenance windows are disabled
func TestMaintenanceWindowDisabledAllowsRotation(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)

	// Secret was generated 2 hours ago, rotation interval is 1 hour
	generatedAt := time.Date(2026, 2, 2, 10, 0, 0, 0, time.UTC)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
				AnnotationRotate:       "1h",
				AnnotationGeneratedAt:  generatedAt.Format(time.RFC3339),
			},
		},
		Data: map[string][]byte{
			"password": []byte("old-password"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

	// Current time is Monday 12:00 UTC - rotation is due
	fixedTime := time.Date(2026, 2, 2, 12, 0, 0, 0, time.UTC)
	mockClock := &MockClock{currentTime: fixedTime}

	cfg := config.NewDefaultConfig()
	// Maintenance windows disabled (default)
	cfg.Rotation.MaintenanceWindows = config.MaintenanceWindowsConfig{
		Enabled: false,
	}

	reconciler := &SecretReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Generator:     gen,
		Config:        cfg,
		EventRecorder: fakeRecorder,
		Clock:         mockClock,
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

	// Fetch the secret - password should have changed
	var updatedSecret corev1.Secret
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updatedSecret)
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}

	if string(updatedSecret.Data["password"]) == "old-password" {
		t.Error("expected password to be rotated when maintenance windows are disabled")
	}
}

// TestMaintenanceWindowRequeueAfterCalculation tests that RequeueAfter is correctly set to next window
func TestMaintenanceWindowRequeueAfterCalculation(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)

	// Secret was generated 2 hours ago, rotation interval is 1 hour
	generatedAt := time.Date(2026, 2, 2, 10, 0, 0, 0, time.UTC) // Monday 10:00 UTC

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
				AnnotationRotate:       "1h",
				AnnotationGeneratedAt:  generatedAt.Format(time.RFC3339),
			},
		},
		Data: map[string][]byte{
			"password": []byte("old-password"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

	// Current time is Monday 12:00 UTC
	fixedTime := time.Date(2026, 2, 2, 12, 0, 0, 0, time.UTC)
	mockClock := &MockClock{currentTime: fixedTime}

	cfg := config.NewDefaultConfig()
	cfg.Rotation.MaintenanceWindows = config.MaintenanceWindowsConfig{
		Enabled: true,
		Windows: []config.MaintenanceWindow{
			{
				Name:      "weekend-night",
				Days:      []string{"saturday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "UTC",
			},
		},
	}

	reconciler := &SecretReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Generator:     gen,
		Config:        cfg,
		EventRecorder: fakeRecorder,
		Clock:         mockClock,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      secret.Name,
			Namespace: secret.Namespace,
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Next Saturday 03:00 UTC is 5 days - 9 hours = 111 hours away
	// Monday 12:00 -> Saturday 03:00 = 4 days 15 hours = 111 hours
	expectedNextWindow := time.Date(2026, 2, 7, 3, 0, 0, 0, time.UTC)
	expectedDuration := expectedNextWindow.Sub(fixedTime)

	if result.RequeueAfter != expectedDuration {
		t.Errorf("expected RequeueAfter to be %v, got %v", expectedDuration, result.RequeueAfter)
	}
}

// TestMaintenanceWindowMultipleWindows tests that the closest window is selected
func TestMaintenanceWindowMultipleWindows(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)

	// Secret was generated 2 hours ago, rotation interval is 1 hour
	generatedAt := time.Date(2026, 2, 2, 10, 0, 0, 0, time.UTC) // Monday 10:00 UTC

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
				AnnotationRotate:       "1h",
				AnnotationGeneratedAt:  generatedAt.Format(time.RFC3339),
			},
		},
		Data: map[string][]byte{
			"password": []byte("old-password"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

	// Current time is Monday 12:00 UTC
	fixedTime := time.Date(2026, 2, 2, 12, 0, 0, 0, time.UTC)
	mockClock := &MockClock{currentTime: fixedTime}

	cfg := config.NewDefaultConfig()
	cfg.Rotation.MaintenanceWindows = config.MaintenanceWindowsConfig{
		Enabled: true,
		Windows: []config.MaintenanceWindow{
			{
				Name:      "weekend-night",
				Days:      []string{"saturday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "UTC",
			},
			{
				Name:      "wednesday-maintenance",
				Days:      []string{"wednesday"},
				StartTime: "02:00",
				EndTime:   "04:00",
				Timezone:  "UTC",
			},
		},
	}

	reconciler := &SecretReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Generator:     gen,
		Config:        cfg,
		EventRecorder: fakeRecorder,
		Clock:         mockClock,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      secret.Name,
			Namespace: secret.Namespace,
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wednesday 02:00 is closer than Saturday 03:00
	// Monday 12:00 -> Wednesday 02:00 = 1 day 14 hours = 38 hours
	expectedNextWindow := time.Date(2026, 2, 4, 2, 0, 0, 0, time.UTC)
	expectedDuration := expectedNextWindow.Sub(fixedTime)

	if result.RequeueAfter != expectedDuration {
		t.Errorf("expected RequeueAfter to be %v (Wednesday window), got %v", expectedDuration, result.RequeueAfter)
	}
}

// TestMaintenanceWindowInitialGenerationNotDeferred tests that initial generation is not affected by maintenance windows
func TestMaintenanceWindowInitialGenerationNotDeferred(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)

	// New secret without any generated data
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
				AnnotationRotate:       "1h",
			},
		},
		Data: map[string][]byte{},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

	// Current time is Monday 12:00 UTC - outside maintenance window
	fixedTime := time.Date(2026, 2, 2, 12, 0, 0, 0, time.UTC)
	mockClock := &MockClock{currentTime: fixedTime}

	cfg := config.NewDefaultConfig()
	cfg.Rotation.MaintenanceWindows = config.MaintenanceWindowsConfig{
		Enabled: true,
		Windows: []config.MaintenanceWindow{
			{
				Name:      "weekend-night",
				Days:      []string{"saturday", "sunday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "UTC",
			},
		},
	}

	reconciler := &SecretReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Generator:     gen,
		Config:        cfg,
		EventRecorder: fakeRecorder,
		Clock:         mockClock,
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

	// Fetch the secret - password should have been generated (initial generation is not deferred)
	var updatedSecret corev1.Secret
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updatedSecret)
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}

	if _, ok := updatedSecret.Data["password"]; !ok {
		t.Error("expected password to be generated even outside maintenance window (initial generation)")
	}
}

// TestGetFieldCurve tests the getFieldCurve method
func TestGetFieldCurve(t *testing.T) {
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
			name:        "field-specific curve",
			annotations: map[string]string{AnnotationCurvePrefix + "signing-key": "P-384"},
			field:       "signing-key",
			expected:    "P-384",
		},
		{
			name: "field-specific overrides default",
			annotations: map[string]string{
				AnnotationCurve:                           "P-256",
				AnnotationCurvePrefix + "signing-key": "P-521",
			},
			field:    "signing-key",
			expected: "P-521",
		},
		{
			name:        "fallback to default curve annotation",
			annotations: map[string]string{AnnotationCurve: "P-384"},
			field:       "signing-key",
			expected:    "P-384",
		},
		{
			name:        "fallback to built-in default P-256",
			annotations: map[string]string{},
			field:       "signing-key",
			expected:    "P-256",
		},
		{
			name:        "nil annotations",
			annotations: nil,
			field:       "signing-key",
			expected:    "P-256",
		},
		{
			name: "different field uses default curve",
			annotations: map[string]string{
				AnnotationCurvePrefix + "other-key": "P-521",
				AnnotationCurve:                     "P-384",
			},
			field:    "signing-key",
			expected: "P-384",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.getFieldCurve(tt.annotations, tt.field)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestReconcileRSAKeypair tests RSA keypair generation via reconciliation
func TestReconcileRSAKeypair(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rsa-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate:              "tls-key",
				AnnotationTypePrefix + "tls-key":    "rsa",
				AnnotationLengthPrefix + "tls-key": "2048",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

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

	var updatedSecret corev1.Secret
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updatedSecret)
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}

	// Verify private key was generated
	privateKey, ok := updatedSecret.Data["tls-key"]
	if !ok {
		t.Fatal("expected tls-key field to be generated")
	}
	if !strings.HasPrefix(string(privateKey), "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("expected private key to be in PEM format")
	}

	// Verify public key was generated
	publicKey, ok := updatedSecret.Data["tls-key.pub"]
	if !ok {
		t.Fatal("expected tls-key.pub field to be generated")
	}
	if !strings.HasPrefix(string(publicKey), "-----BEGIN RSA PUBLIC KEY-----") {
		t.Error("expected public key to be in PEM format")
	}

	// Verify generated-at annotation
	if _, ok := updatedSecret.Annotations[AnnotationGeneratedAt]; !ok {
		t.Error("expected generated-at annotation to be set")
	}
}

// TestReconcileECDSAKeypair tests ECDSA keypair generation via reconciliation
func TestReconcileECDSAKeypair(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	tests := []struct {
		name  string
		curve string
	}{
		{"P-256", "P-256"},
		{"P-384", "P-384"},
		{"P-521", "P-521"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ecdsa-secret",
					Namespace: "default",
					Annotations: map[string]string{
						AnnotationAutogenerate:                  "signing-key",
						AnnotationTypePrefix + "signing-key":   "ecdsa",
						AnnotationCurvePrefix + "signing-key": tt.curve,
					},
				},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(secret).
				Build()

			gen := generator.NewSecretGenerator()
			fakeRecorder := NewTestEventRecorder(10)

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

			var updatedSecret corev1.Secret
			err = fakeClient.Get(context.Background(), req.NamespacedName, &updatedSecret)
			if err != nil {
				t.Fatalf("failed to get secret: %v", err)
			}

			// Verify private key was generated
			privateKey, ok := updatedSecret.Data["signing-key"]
			if !ok {
				t.Fatal("expected signing-key field to be generated")
			}
			if !strings.HasPrefix(string(privateKey), "-----BEGIN EC PRIVATE KEY-----") {
				t.Errorf("expected EC private key PEM format, got: %s", string(privateKey)[:50])
			}

			// Verify public key was generated
			publicKey, ok := updatedSecret.Data["signing-key.pub"]
			if !ok {
				t.Fatal("expected signing-key.pub field to be generated")
			}
			if !strings.HasPrefix(string(publicKey), "-----BEGIN PUBLIC KEY-----") {
				t.Errorf("expected public key PEM format, got: %s", string(publicKey)[:50])
			}
		})
	}
}

// TestReconcileECDSAKeypairDefaultCurve tests ECDSA with default curve (P-256)
func TestReconcileECDSAKeypairDefaultCurve(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ecdsa-default-curve",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate:                "signing-key",
				AnnotationTypePrefix + "signing-key": "ecdsa",
				// No curve annotation → should default to P-256
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

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

	var updatedSecret corev1.Secret
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updatedSecret)
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}

	if _, ok := updatedSecret.Data["signing-key"]; !ok {
		t.Fatal("expected signing-key field to be generated")
	}
	if _, ok := updatedSecret.Data["signing-key.pub"]; !ok {
		t.Fatal("expected signing-key.pub field to be generated")
	}
}

// TestReconcileEd25519Keypair tests Ed25519 keypair generation via reconciliation
func TestReconcileEd25519Keypair(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ed25519-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate:              "ssh-key",
				AnnotationTypePrefix + "ssh-key": "ed25519",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

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

	var updatedSecret corev1.Secret
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updatedSecret)
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}

	// Verify private key was generated
	privateKey, ok := updatedSecret.Data["ssh-key"]
	if !ok {
		t.Fatal("expected ssh-key field to be generated")
	}
	if !strings.HasPrefix(string(privateKey), "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("expected private key PEM format, got: %s", string(privateKey)[:40])
	}

	// Verify public key was generated
	publicKey, ok := updatedSecret.Data["ssh-key.pub"]
	if !ok {
		t.Fatal("expected ssh-key.pub field to be generated")
	}
	if !strings.HasPrefix(string(publicKey), "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("expected public key PEM format, got: %s", string(publicKey)[:40])
	}
}

// TestReconcileKeypairExistingValueNotOverwritten tests that existing keypair values are preserved
func TestReconcileKeypairExistingValueNotOverwritten(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-keypair",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate:              "tls-key",
				AnnotationTypePrefix + "tls-key": "rsa",
				AnnotationLengthPrefix + "tls-key": "2048",
			},
		},
		Data: map[string][]byte{
			"tls-key": []byte("existing-private-key"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

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

	var updatedSecret corev1.Secret
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updatedSecret)
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}

	// Verify existing value was not overwritten
	if string(updatedSecret.Data["tls-key"]) != "existing-private-key" {
		t.Error("expected existing private key value to be preserved")
	}

	// Verify no public key was generated (since private key already existed)
	if _, ok := updatedSecret.Data["tls-key.pub"]; ok {
		t.Error("expected no public key to be generated when private key already exists")
	}
}

// TestReconcileMixedKeypairAndString tests generating mixed types in one secret
func TestReconcileMixedKeypairAndString(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mixed-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate:               "password,tls-key,ssh-key",
				AnnotationType:                        "string",
				AnnotationLength:                      "24",
				AnnotationTypePrefix + "tls-key":     "rsa",
				AnnotationLengthPrefix + "tls-key":   "2048",
				AnnotationTypePrefix + "ssh-key":     "ed25519",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

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

	var updatedSecret corev1.Secret
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updatedSecret)
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}

	// Verify password (string type)
	password, ok := updatedSecret.Data["password"]
	if !ok {
		t.Fatal("expected password field to be generated")
	}
	if len(password) != 24 {
		t.Errorf("expected password length 24, got %d", len(password))
	}

	// Verify RSA keypair
	if _, ok := updatedSecret.Data["tls-key"]; !ok {
		t.Fatal("expected tls-key field to be generated")
	}
	if _, ok := updatedSecret.Data["tls-key.pub"]; !ok {
		t.Fatal("expected tls-key.pub field to be generated")
	}

	// Verify Ed25519 keypair
	if _, ok := updatedSecret.Data["ssh-key"]; !ok {
		t.Fatal("expected ssh-key field to be generated")
	}
	if _, ok := updatedSecret.Data["ssh-key.pub"]; !ok {
		t.Fatal("expected ssh-key.pub field to be generated")
	}

	// Verify no spurious .pub for password
	if _, ok := updatedSecret.Data["password.pub"]; ok {
		t.Error("string type should not generate a .pub field")
	}
}

// TestReconcileECDSAInvalidCurve tests that an invalid ECDSA curve emits a warning
func TestReconcileECDSAInvalidCurve(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "invalid-curve-secret",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAutogenerate:                  "signing-key",
				AnnotationTypePrefix + "signing-key":   "ecdsa",
				AnnotationCurvePrefix + "signing-key": "P-999",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	gen := generator.NewSecretGenerator()
	fakeRecorder := NewTestEventRecorder(10)

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

	// Verify warning event was emitted
	select {
	case event := <-fakeRecorder.Events:
		expectedPrefix := fmt.Sprintf("%s %s", corev1.EventTypeWarning, EventReasonGenerationFailed)
		if !strings.HasPrefix(event, expectedPrefix) {
			t.Errorf("expected event to start with %q, got %q", expectedPrefix, event)
		}
	default:
		t.Error("expected a warning event for invalid curve")
	}

	// Verify no data was written
	var updatedSecret corev1.Secret
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updatedSecret)
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}
	if _, ok := updatedSecret.Data["signing-key"]; ok {
		t.Error("expected no data to be written for invalid curve")
	}
}
