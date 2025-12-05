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

package replicator

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMatchNamespace(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		pattern   string
		want      bool
		wantErr   bool
	}{
		// Exact matches
		{
			name:      "exact match",
			namespace: "production",
			pattern:   "production",
			want:      true,
			wantErr:   false,
		},
		{
			name:      "exact no match",
			namespace: "staging",
			pattern:   "production",
			want:      false,
			wantErr:   false,
		},
		// Wildcard *
		{
			name:      "wildcard * matches all",
			namespace: "production",
			pattern:   "*",
			want:      true,
			wantErr:   false,
		},
		{
			name:      "wildcard * prefix",
			namespace: "namespace-123",
			pattern:   "namespace-*",
			want:      true,
			wantErr:   false,
		},
		{
			name:      "wildcard * prefix no match",
			namespace: "other-123",
			pattern:   "namespace-*",
			want:      false,
			wantErr:   false,
		},
		{
			name:      "wildcard * suffix",
			namespace: "prod-namespace",
			pattern:   "*-namespace",
			want:      true,
			wantErr:   false,
		},
		{
			name:      "wildcard * middle",
			namespace: "prod-app-namespace",
			pattern:   "prod-*-namespace",
			want:      true,
			wantErr:   false,
		},
		// Wildcard ?
		{
			name:      "wildcard ? single char",
			namespace: "prod1",
			pattern:   "prod?",
			want:      true,
			wantErr:   false,
		},
		{
			name:      "wildcard ? no match too long",
			namespace: "prod123",
			pattern:   "prod?",
			want:      false,
			wantErr:   false,
		},
		{
			name:      "wildcard ? multiple",
			namespace: "ns-12",
			pattern:   "ns-??",
			want:      true,
			wantErr:   false,
		},
		// Character classes
		{
			name:      "char class [abc]",
			namespace: "prod-a",
			pattern:   "prod-[abc]",
			want:      true,
			wantErr:   false,
		},
		{
			name:      "char class [abc] no match",
			namespace: "prod-x",
			pattern:   "prod-[abc]",
			want:      false,
			wantErr:   false,
		},
		{
			name:      "char class [a-z]",
			namespace: "prod-m",
			pattern:   "prod-[a-z]",
			want:      true,
			wantErr:   false,
		},
		{
			name:      "char class [a-z] no match digit",
			namespace: "prod-5",
			pattern:   "prod-[a-z]",
			want:      false,
			wantErr:   false,
		},
		{
			name:      "char class [0-9]",
			namespace: "namespace-5",
			pattern:   "namespace-[0-9]",
			want:      true,
			wantErr:   false,
		},
		{
			name:      "char class [0-9] no match letter",
			namespace: "namespace-a",
			pattern:   "namespace-[0-9]",
			want:      false,
			wantErr:   false,
		},
		// Complex patterns
		{
			name:      "complex pattern with multiple wildcards",
			namespace: "prod-app-123-namespace",
			pattern:   "prod-*-[0-9]*-namespace",
			want:      true,
			wantErr:   false,
		},
		// Invalid patterns
		{
			name:      "invalid pattern unclosed bracket",
			namespace: "test",
			pattern:   "test-[abc",
			want:      false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MatchNamespace(tt.namespace, tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("MatchNamespace() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("MatchNamespace() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateReplication(t *testing.T) {
	tests := []struct {
		name            string
		sourceNamespace string
		sourceAllowlist string
		targetNamespace string
		want            bool
		wantErr         bool
	}{
		{
			name:            "exact match single namespace",
			sourceNamespace: "production",
			sourceAllowlist: "staging",
			targetNamespace: "staging",
			want:            true,
			wantErr:         false,
		},
		{
			name:            "no match single namespace",
			sourceNamespace: "production",
			sourceAllowlist: "staging",
			targetNamespace: "development",
			want:            false,
			wantErr:         true,
		},
		{
			name:            "match in comma-separated list",
			sourceNamespace: "production",
			sourceAllowlist: "staging,development,qa",
			targetNamespace: "qa",
			want:            true,
			wantErr:         false,
		},
		{
			name:            "wildcard * matches all",
			sourceNamespace: "production",
			sourceAllowlist: "*",
			targetNamespace: "any-namespace",
			want:            true,
			wantErr:         false,
		},
		{
			name:            "pattern with wildcard",
			sourceNamespace: "production",
			sourceAllowlist: "namespace-*",
			targetNamespace: "namespace-123",
			want:            true,
			wantErr:         false,
		},
		{
			name:            "pattern no match",
			sourceNamespace: "production",
			sourceAllowlist: "namespace-*",
			targetNamespace: "other-123",
			want:            false,
			wantErr:         true,
		},
		{
			name:            "empty allowlist",
			sourceNamespace: "production",
			sourceAllowlist: "",
			targetNamespace: "staging",
			want:            false,
			wantErr:         true,
		},
		{
			name:            "whitespace in list",
			sourceNamespace: "production",
			sourceAllowlist: "staging , development , qa",
			targetNamespace: "development",
			want:            true,
			wantErr:         false,
		},
		{
			name:            "invalid pattern in list",
			sourceNamespace: "production",
			sourceAllowlist: "staging,[invalid",
			targetNamespace: "staging",
			want:            true,
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateReplication(tt.sourceNamespace, tt.sourceAllowlist, tt.targetNamespace)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateReplication() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateReplication() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReplicateSecret(t *testing.T) {
	source := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "source-secret",
			Namespace: "production",
		},
		Data: map[string][]byte{
			"username": []byte("produser"),
			"password": []byte("prodpass"),
		},
	}

	tests := []struct {
		name   string
		target *corev1.Secret
	}{
		{
			name: "empty target",
			target: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "target-secret",
					Namespace: "staging",
				},
			},
		},
		{
			name: "target with existing data (should overwrite)",
			target: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "target-secret",
					Namespace: "staging",
				},
				Data: map[string][]byte{
					"username": []byte("olduser"),
					"oldkey":   []byte("oldvalue"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ReplicateSecret(source, tt.target)

			// Check data was copied
			if len(tt.target.Data) < len(source.Data) {
				t.Errorf("target data length = %d, want at least %d", len(tt.target.Data), len(source.Data))
			}

			// Check all source keys exist in target
			for key, value := range source.Data {
				targetValue, exists := tt.target.Data[key]
				if !exists {
					t.Errorf("target missing key %q", key)
					continue
				}
				if string(targetValue) != string(value) {
					t.Errorf("target[%q] = %q, want %q", key, targetValue, value)
				}
			}

			// Check annotations
			if tt.target.Annotations == nil {
				t.Fatal("target annotations is nil")
			}

			expectedReplicatedFrom := "production/source-secret"
			if tt.target.Annotations[AnnotationReplicatedFrom] != expectedReplicatedFrom {
				t.Errorf("replicated-from = %q, want %q",
					tt.target.Annotations[AnnotationReplicatedFrom], expectedReplicatedFrom)
			}

			// Check timestamp exists and is valid
			timestamp := tt.target.Annotations[AnnotationLastReplicatedAt]
			if timestamp == "" {
				t.Error("last-replicated-at annotation is empty")
			}
			_, err := time.Parse(time.RFC3339, timestamp)
			if err != nil {
				t.Errorf("last-replicated-at is not valid RFC3339: %v", err)
			}
		})
	}
}

func TestParseSourceReference(t *testing.T) {
	tests := []struct {
		name          string
		sourceRef     string
		wantNamespace string
		wantName      string
		wantErr       bool
	}{
		{
			name:          "valid reference",
			sourceRef:     "production/db-credentials",
			wantNamespace: "production",
			wantName:      "db-credentials",
			wantErr:       false,
		},
		{
			name:          "valid with whitespace",
			sourceRef:     " production / db-credentials ",
			wantNamespace: "production",
			wantName:      "db-credentials",
			wantErr:       false,
		},
		{
			name:      "invalid no slash",
			sourceRef: "production-db-credentials",
			wantErr:   true,
		},
		{
			name:      "invalid empty namespace",
			sourceRef: "/db-credentials",
			wantErr:   true,
		},
		{
			name:      "invalid empty name",
			sourceRef: "production/",
			wantErr:   true,
		},
		{
			name:      "invalid empty string",
			sourceRef: "",
			wantErr:   true,
		},
		{
			name:          "valid with multiple slashes (takes first two parts)",
			sourceRef:     "namespace/secret/extra",
			wantNamespace: "namespace",
			wantName:      "secret/extra",
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotNamespace, gotName, err := ParseSourceReference(tt.sourceRef)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSourceReference() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if gotNamespace != tt.wantNamespace {
					t.Errorf("ParseSourceReference() namespace = %v, want %v", gotNamespace, tt.wantNamespace)
				}
				if gotName != tt.wantName {
					t.Errorf("ParseSourceReference() name = %v, want %v", gotName, tt.wantName)
				}
			}
		})
	}
}

func TestParseTargetNamespaces(t *testing.T) {
	tests := []struct {
		name     string
		targetNS string
		want     []string
	}{
		{
			name:     "single namespace",
			targetNS: "staging",
			want:     []string{"staging"},
		},
		{
			name:     "multiple namespaces",
			targetNS: "staging,development,qa",
			want:     []string{"staging", "development", "qa"},
		},
		{
			name:     "with whitespace",
			targetNS: "staging , development , qa",
			want:     []string{"staging", "development", "qa"},
		},
		{
			name:     "empty string",
			targetNS: "",
			want:     nil,
		},
		{
			name:     "trailing comma",
			targetNS: "staging,development,",
			want:     []string{"staging", "development"},
		},
		{
			name:     "empty parts",
			targetNS: "staging,,development",
			want:     []string{"staging", "development"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseTargetNamespaces(tt.targetNS)
			if len(got) != len(tt.want) {
				t.Errorf("ParseTargetNamespaces() length = %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ParseTargetNamespaces()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestFinalizers(t *testing.T) {
	t.Run("HasFinalizer", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Finalizers: []string{"some-other-finalizer", FinalizerReplicateToCleanup},
			},
		}
		if !HasFinalizer(secret) {
			t.Error("HasFinalizer() = false, want true")
		}

		secret.Finalizers = []string{"some-other-finalizer"}
		if HasFinalizer(secret) {
			t.Error("HasFinalizer() = true, want false")
		}

		secret.Finalizers = nil
		if HasFinalizer(secret) {
			t.Error("HasFinalizer() = true, want false")
		}
	})

	t.Run("AddFinalizer", func(t *testing.T) {
		secret := &corev1.Secret{}
		AddFinalizer(secret)

		if len(secret.Finalizers) != 1 {
			t.Errorf("finalizers length = %d, want 1", len(secret.Finalizers))
		}
		if secret.Finalizers[0] != FinalizerReplicateToCleanup {
			t.Errorf("finalizer = %q, want %q", secret.Finalizers[0], FinalizerReplicateToCleanup)
		}

		// Add again - should not duplicate
		AddFinalizer(secret)
		if len(secret.Finalizers) != 1 {
			t.Errorf("finalizers length after second add = %d, want 1", len(secret.Finalizers))
		}
	})

	t.Run("RemoveFinalizer", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Finalizers: []string{"other-finalizer", FinalizerReplicateToCleanup, "another-finalizer"},
			},
		}

		RemoveFinalizer(secret)

		if len(secret.Finalizers) != 2 {
			t.Errorf("finalizers length = %d, want 2", len(secret.Finalizers))
		}
		for _, f := range secret.Finalizers {
			if f == FinalizerReplicateToCleanup {
				t.Errorf("finalizer still present after removal")
			}
		}
	})
}

func TestIsOwnedByUs(t *testing.T) {
	tests := []struct {
		name           string
		secret         *corev1.Secret
		expectedSource string
		want           bool
	}{
		{
			name: "owned by us",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationReplicatedFrom: "production/db-credentials",
					},
				},
			},
			expectedSource: "production/db-credentials",
			want:           true,
		},
		{
			name: "different source",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationReplicatedFrom: "staging/db-credentials",
					},
				},
			},
			expectedSource: "production/db-credentials",
			want:           false,
		},
		{
			name: "no annotation",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{},
				},
			},
			expectedSource: "production/db-credentials",
			want:           false,
		},
		{
			name:           "nil annotations",
			secret:         &corev1.Secret{},
			expectedSource: "production/db-credentials",
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsOwnedByUs(tt.secret, tt.expectedSource)
			if got != tt.want {
				t.Errorf("IsOwnedByUs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsBeingDeleted(t *testing.T) {
	now := metav1.Now()

	tests := []struct {
		name   string
		secret *corev1.Secret
		want   bool
	}{
		{
			name: "being deleted",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					DeletionTimestamp: &now,
				},
			},
			want: true,
		},
		{
			name:   "not being deleted",
			secret: &corev1.Secret{},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsBeingDeleted(tt.secret)
			if got != tt.want {
				t.Errorf("IsBeingDeleted() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasConflictingAnnotations(t *testing.T) {
	tests := []struct {
		name   string
		secret *corev1.Secret
		want   bool
	}{
		{
			name: "both annotations present - conflict",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationPrefix + "autogenerate": "password",
						AnnotationReplicateFrom:           "production/db-credentials",
					},
				},
			},
			want: true,
		},
		{
			name: "only autogenerate - no conflict",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationPrefix + "autogenerate": "password",
					},
				},
			},
			want: false,
		},
		{
			name: "only replicate-from - no conflict",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationReplicateFrom: "production/db-credentials",
					},
				},
			},
			want: false,
		},
		{
			name: "neither annotation - no conflict",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{},
				},
			},
			want: false,
		},
		{
			name:   "nil annotations - no conflict",
			secret: &corev1.Secret{},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasConflictingAnnotations(tt.secret)
			if got != tt.want {
				t.Errorf("HasConflictingAnnotations() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateReplicatedSecret(t *testing.T) {
	source := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-credentials",
			Namespace: "production",
			Labels: map[string]string{
				"app": "myapp",
				"env": "prod",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"username": []byte("produser"),
			"password": []byte("prodpass"),
		},
	}

	target := CreateReplicatedSecret(source, "staging")

	// Check basic metadata
	if target.Name != source.Name {
		t.Errorf("target name = %q, want %q", target.Name, source.Name)
	}
	if target.Namespace != "staging" {
		t.Errorf("target namespace = %q, want %q", target.Namespace, "staging")
	}
	if target.Type != source.Type {
		t.Errorf("target type = %q, want %q", target.Type, source.Type)
	}

	// Check labels copied
	if len(target.Labels) != len(source.Labels) {
		t.Errorf("target labels length = %d, want %d", len(target.Labels), len(source.Labels))
	}
	for key, value := range source.Labels {
		if target.Labels[key] != value {
			t.Errorf("target label[%q] = %q, want %q", key, target.Labels[key], value)
		}
	}

	// Check data copied
	if len(target.Data) != len(source.Data) {
		t.Errorf("target data length = %d, want %d", len(target.Data), len(source.Data))
	}
	for key, value := range source.Data {
		if string(target.Data[key]) != string(value) {
			t.Errorf("target data[%q] = %q, want %q", key, target.Data[key], value)
		}
	}

	// Check annotations
	expectedReplicatedFrom := "production/db-credentials"
	if target.Annotations[AnnotationReplicatedFrom] != expectedReplicatedFrom {
		t.Errorf("replicated-from = %q, want %q",
			target.Annotations[AnnotationReplicatedFrom], expectedReplicatedFrom)
	}

	timestamp := target.Annotations[AnnotationLastReplicatedAt]
	if timestamp == "" {
		t.Error("last-replicated-at annotation is empty")
	}
	_, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		t.Errorf("last-replicated-at is not valid RFC3339: %v", err)
	}
}
