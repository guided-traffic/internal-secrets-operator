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

func TestReplicateConfigMap(t *testing.T) {
	tests := []struct {
		name           string
		source         *corev1.ConfigMap
		target         *corev1.ConfigMap
		expectedData   map[string]string
		expectedBinary map[string][]byte
	}{
		{
			name: "replicates data to empty target",
			source: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "ca-bundle", Namespace: "garden"},
				Data: map[string]string{
					"ca.crt": "cert-content",
					"config": "key=value",
				},
			},
			target: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "ca-bundle", Namespace: "shoot-a"},
			},
			expectedData: map[string]string{
				"ca.crt": "cert-content",
				"config": "key=value",
			},
		},
		{
			name: "overwrites existing target data",
			source: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "ca-bundle", Namespace: "garden"},
				Data:       map[string]string{"ca.crt": "new-cert"},
			},
			target: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "ca-bundle", Namespace: "shoot-a"},
				Data: map[string]string{
					"ca.crt": "old-cert",
					"extra":  "kept",
				},
			},
			expectedData: map[string]string{
				"ca.crt": "new-cert",
				"extra":  "kept",
			},
		},
		{
			name: "replicates binary data",
			source: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "binary-cm", Namespace: "garden"},
				Data:       map[string]string{"key": "value"},
				BinaryData: map[string][]byte{"blob": {0x01, 0x02, 0x03}},
			},
			target: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "binary-cm", Namespace: "shoot-a"},
			},
			expectedData:   map[string]string{"key": "value"},
			expectedBinary: map[string][]byte{"blob": {0x01, 0x02, 0x03}},
		},
		{
			name: "source without data still sets annotations",
			source: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "empty-cm", Namespace: "garden"},
			},
			target: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "empty-cm", Namespace: "shoot-a"},
			},
			expectedData: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := time.Now().Add(-time.Second)
			ReplicateConfigMap(tt.source, tt.target)

			if len(tt.target.Data) != len(tt.expectedData) {
				t.Errorf("Data has %d entries, want %d", len(tt.target.Data), len(tt.expectedData))
			}
			for key, want := range tt.expectedData {
				if got := tt.target.Data[key]; got != want {
					t.Errorf("Data[%s] = %q, want %q", key, got, want)
				}
			}

			for key, want := range tt.expectedBinary {
				got := tt.target.BinaryData[key]
				if string(got) != string(want) {
					t.Errorf("BinaryData[%s] = %v, want %v", key, got, want)
				}
			}

			// Annotations must reference the source
			wantRef := tt.source.Namespace + "/" + tt.source.Name
			if got := tt.target.Annotations[AnnotationReplicatedFrom]; got != wantRef {
				t.Errorf("replicated-from annotation = %q, want %q", got, wantRef)
			}
			ts := tt.target.Annotations[AnnotationLastReplicatedAt]
			if ts == "" {
				t.Fatal("last-replicated-at annotation missing")
			}
			parsed, err := time.Parse(time.RFC3339, ts)
			if err != nil {
				t.Fatalf("last-replicated-at is not RFC3339: %v", err)
			}
			if parsed.Before(before) {
				t.Errorf("last-replicated-at %v is unexpectedly old", parsed)
			}
		})
	}
}

func TestConfigMapBeingDeleted(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: "default"},
	}
	if IsBeingDeleted(cm) {
		t.Error("ConfigMap without DeletionTimestamp should not be considered deleted")
	}

	now := metav1.Now()
	cm.DeletionTimestamp = &now
	if !IsBeingDeleted(cm) {
		t.Error("ConfigMap with DeletionTimestamp should be considered deleted")
	}
}

func TestConfigMapFinalizers(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: "default"},
	}

	if HasFinalizer(cm) {
		t.Error("new ConfigMap should not have the finalizer")
	}

	AddFinalizer(cm)
	if !HasFinalizer(cm) {
		t.Error("finalizer should be present after AddFinalizer")
	}

	// Adding twice must not duplicate
	AddFinalizer(cm)
	if len(cm.Finalizers) != 1 {
		t.Errorf("expected 1 finalizer, got %d", len(cm.Finalizers))
	}

	// Other finalizers must survive removal
	cm.Finalizers = append(cm.Finalizers, "other-finalizer")
	RemoveFinalizer(cm)
	if HasFinalizer(cm) {
		t.Error("finalizer should be gone after RemoveFinalizer")
	}
	if len(cm.Finalizers) != 1 || cm.Finalizers[0] != "other-finalizer" {
		t.Errorf("other finalizers should be preserved, got %v", cm.Finalizers)
	}
}

func TestCreateReplicatedConfigMap(t *testing.T) {
	source := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-config",
			Namespace: "production",
			Labels:    map[string]string{"app": "demo"},
			Annotations: map[string]string{
				AnnotationReplicateTo: "staging",
			},
		},
		Data:       map[string]string{"setting": "value"},
		BinaryData: map[string][]byte{"blob": {0x01, 0x02}},
	}

	target := CreateReplicatedConfigMap(source, "staging")

	if target.Name != "app-config" || target.Namespace != "staging" {
		t.Errorf("unexpected target identity: %s/%s", target.Namespace, target.Name)
	}
	if target.Data["setting"] != "value" {
		t.Errorf("Data not copied, got %v", target.Data)
	}
	if string(target.BinaryData["blob"]) != string([]byte{0x01, 0x02}) {
		t.Errorf("BinaryData not copied, got %v", target.BinaryData)
	}
	if target.Labels["app"] != "demo" {
		t.Errorf("Labels not copied, got %v", target.Labels)
	}
	if target.Annotations[AnnotationReplicatedFrom] != "production/app-config" {
		t.Errorf("replicated-from = %q, want %q", target.Annotations[AnnotationReplicatedFrom], "production/app-config")
	}
	if target.Annotations[AnnotationLastReplicatedAt] == "" {
		t.Error("last-replicated-at annotation missing")
	}
	// The source's replication annotations must NOT be copied to the target
	if target.Annotations[AnnotationReplicateTo] != "" {
		t.Error("replicate-to annotation must not be copied to the pushed ConfigMap")
	}

	// Source without binaryData must not produce a binaryData map
	plainSource := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "plain", Namespace: "production"},
		Data:       map[string]string{"key": "value"},
	}
	plainTarget := CreateReplicatedConfigMap(plainSource, "staging")
	if plainTarget.BinaryData != nil {
		t.Errorf("expected nil BinaryData, got %v", plainTarget.BinaryData)
	}
}
