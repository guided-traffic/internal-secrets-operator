//go:build e2e
// +build e2e

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

package e2e

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// AnnotationPrefix is the prefix for all secret operator annotations
	AnnotationPrefix = "secgen.gtrfc.com/"

	// AnnotationAutogenerate specifies which fields to auto-generate
	AnnotationAutogenerate = AnnotationPrefix + "autogenerate"

	// AnnotationType specifies the type of generated value
	AnnotationType = AnnotationPrefix + "type"

	// AnnotationLength specifies the length of the generated value
	AnnotationLength = AnnotationPrefix + "length"

	// AnnotationTypePrefix is the prefix for field-specific type annotations
	AnnotationTypePrefix = AnnotationPrefix + "type."

	// AnnotationLengthPrefix is the prefix for field-specific length annotations
	AnnotationLengthPrefix = AnnotationPrefix + "length."

	// AnnotationGeneratedAt indicates when the value was generated
	AnnotationGeneratedAt = AnnotationPrefix + "generated-at"

	// testNamespace is the namespace used for E2E tests
	testNamespace = "default"

	// pollInterval is the interval for polling operations
	pollInterval = 1 * time.Second

	// pollTimeout is the timeout for polling operations
	pollTimeout = 60 * time.Second
)

var clientset *kubernetes.Clientset

// testSecretNames holds all secret names created during tests for cleanup
var testSecretNames = []string{
	"test-autogenerate",
	"test-multi-field",
	"test-bytes",
	"test-regenerate-by-deletion",
	"test-no-annotation",
	"test-existing-value",
	"test-field-specific",
}

func TestMain(m *testing.M) {
	// Build kubeconfig
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			panic(err)
		}
		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		panic(err)
	}

	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}

	// Cleanup any leftover test secrets before running tests
	cleanupTestSecrets()

	code := m.Run()

	// Cleanup test secrets after all tests
	cleanupTestSecrets()

	os.Exit(code)
}

func cleanupTestSecrets() {
	ctx := context.Background()
	for _, name := range testSecretNames {
		_ = clientset.CoreV1().Secrets(testNamespace).Delete(ctx, name, metav1.DeleteOptions{})
	}
}

func cleanupSecret(t *testing.T, name string) {
	ctx := context.Background()
	err := clientset.CoreV1().Secrets(testNamespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		t.Logf("Warning: Failed to delete secret %s: %v", name, err)
	}
}

func TestSecretAutoGeneration(t *testing.T) {
	defer cleanupSecret(t, "test-autogenerate")

	ctx := context.Background()

	// Create a secret with autogenerate annotation
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-autogenerate",
			Namespace: testNamespace,
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
				AnnotationType:         "string",
				AnnotationLength:       "32",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"username": []byte("testuser"),
		},
	}

	_, err := clientset.CoreV1().Secrets(testNamespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Wait for the operator to process the secret
	var processedSecret *corev1.Secret
	err = wait.PollUntilContextTimeout(ctx, pollInterval, pollTimeout, true, func(ctx context.Context) (bool, error) {
		s, err := clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-autogenerate", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		// Check if password field was generated
		if _, ok := s.Data["password"]; ok {
			// Check if generated-at annotation was set
			if s.Annotations[AnnotationGeneratedAt] != "" {
				processedSecret = s
				return true, nil
			}
		}
		return false, nil
	})

	if err != nil {
		t.Fatalf("Timeout waiting for secret to be processed: %v", err)
	}

	// Verify the generated password
	password := string(processedSecret.Data["password"])
	if len(password) != 32 {
		t.Errorf("Expected password length 32, got %d", len(password))
	}

	// Verify username was not modified
	if string(processedSecret.Data["username"]) != "testuser" {
		t.Errorf("Username was unexpectedly modified")
	}

	// Verify generated-at annotation was set
	if processedSecret.Annotations[AnnotationGeneratedAt] == "" {
		t.Error("Expected generated-at annotation to be set")
	}

	t.Logf("Secret successfully processed with password length: %d", len(password))
}

func TestSecretMultiFieldGeneration(t *testing.T) {
	defer cleanupSecret(t, "test-multi-field")

	ctx := context.Background()

	// Create a secret with multiple fields to generate
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-multi-field",
			Namespace: testNamespace,
			Annotations: map[string]string{
				AnnotationAutogenerate: "password,api-key,token",
				AnnotationType:         "string",
				AnnotationLength:       "24",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"username": []byte("admin"),
		},
	}

	_, err := clientset.CoreV1().Secrets(testNamespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Wait for the operator to process the secret
	var processedSecret *corev1.Secret
	err = wait.PollUntilContextTimeout(ctx, pollInterval, pollTimeout, true, func(ctx context.Context) (bool, error) {
		s, err := clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-multi-field", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		// Check if all fields were generated
		_, hasPassword := s.Data["password"]
		_, hasApiKey := s.Data["api-key"]
		_, hasToken := s.Data["token"]

		if hasPassword && hasApiKey && hasToken && s.Annotations[AnnotationGeneratedAt] != "" {
			processedSecret = s
			return true, nil
		}
		return false, nil
	})

	if err != nil {
		t.Fatalf("Timeout waiting for secret to be processed: %v", err)
	}

	// Verify all generated fields
	fields := []string{"password", "api-key", "token"}
	for _, field := range fields {
		value := string(processedSecret.Data[field])
		if len(value) != 24 {
			t.Errorf("Expected %s length 24, got %d", field, len(value))
		}
	}

	// Verify fields are unique
	if string(processedSecret.Data["password"]) == string(processedSecret.Data["api-key"]) {
		t.Error("Expected password and api-key to be different")
	}

	t.Log("Multiple fields successfully generated")
}

func TestSecretBytesGeneration(t *testing.T) {
	defer cleanupSecret(t, "test-bytes")

	ctx := context.Background()

	// Create a secret with bytes type
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-bytes",
			Namespace: testNamespace,
			Annotations: map[string]string{
				AnnotationAutogenerate: "encryption-key",
				AnnotationType:         "bytes",
				AnnotationLength:       "32",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{},
	}

	_, err := clientset.CoreV1().Secrets(testNamespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Wait for the operator to process the secret
	var processedSecret *corev1.Secret
	err = wait.PollUntilContextTimeout(ctx, pollInterval, pollTimeout, true, func(ctx context.Context) (bool, error) {
		s, err := clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-bytes", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		if _, ok := s.Data["encryption-key"]; ok {
			if s.Annotations[AnnotationGeneratedAt] != "" {
				processedSecret = s
				return true, nil
			}
		}
		return false, nil
	})

	if err != nil {
		t.Fatalf("Timeout waiting for secret to be processed: %v", err)
	}

	// Verify the generated value has correct length (32 raw bytes)
	encryptionKey := processedSecret.Data["encryption-key"]
	if len(encryptionKey) != 32 {
		t.Errorf("Expected encryption-key length 32 bytes, got %d", len(encryptionKey))
	}

	t.Logf("Bytes key successfully generated with length: %d bytes", len(encryptionKey))
}

func TestSecretRegenerationByKeyDeletion(t *testing.T) {
	defer cleanupSecret(t, "test-regenerate-by-deletion")

	ctx := context.Background()

	// Create initial secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-regenerate-by-deletion",
			Namespace: testNamespace,
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
				AnnotationType:         "string",
				AnnotationLength:       "32",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{},
	}

	_, err := clientset.CoreV1().Secrets(testNamespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Wait for initial generation
	var originalPassword string
	err = wait.PollUntilContextTimeout(ctx, pollInterval, pollTimeout, true, func(ctx context.Context) (bool, error) {
		s, err := clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-regenerate-by-deletion", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		if pwd, ok := s.Data["password"]; ok {
			if s.Annotations[AnnotationGeneratedAt] != "" {
				originalPassword = string(pwd)
				return true, nil
			}
		}
		return false, nil
	})

	if err != nil {
		t.Fatalf("Timeout waiting for initial secret generation: %v", err)
	}

	t.Logf("Original password generated: %s...", originalPassword[:8])

	// Delete the password key to trigger regeneration
	currentSecret, err := clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-regenerate-by-deletion", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}

	delete(currentSecret.Data, "password")
	_, err = clientset.CoreV1().Secrets(testNamespace).Update(ctx, currentSecret, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Failed to update secret after deleting password key: %v", err)
	}

	// Wait for regeneration - check that password exists again with a different value
	var newPassword string
	err = wait.PollUntilContextTimeout(ctx, pollInterval, pollTimeout, true, func(ctx context.Context) (bool, error) {
		s, err := clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-regenerate-by-deletion", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		// Check if password was regenerated (exists and is different)
		if pwd, ok := s.Data["password"]; ok {
			newPassword = string(pwd)
			// Password was regenerated if it exists (we deleted it, so any value means regeneration)
			return true, nil
		}
		return false, nil
	})

	if err != nil {
		t.Fatalf("Timeout waiting for secret regeneration: %v", err)
	}

	// The new password should be different from the original (extremely unlikely to be the same)
	if newPassword == originalPassword {
		t.Error("Expected password to be regenerated with different value")
	}

	t.Logf("Password successfully regenerated by key deletion: %s...", newPassword[:8])
}

func TestSecretWithoutAnnotationNotProcessed(t *testing.T) {
	defer cleanupSecret(t, "test-no-annotation")

	ctx := context.Background()

	// Create a secret without autogenerate annotation
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-no-annotation",
			Namespace: testNamespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"username": []byte("testuser"),
			"password": []byte("manual-password"),
		},
	}

	_, err := clientset.CoreV1().Secrets(testNamespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Wait a bit to ensure the operator had time to process
	time.Sleep(5 * time.Second)

	// Verify the secret was not modified
	s, err := clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-no-annotation", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}

	// Check that no operator annotations were added
	if _, ok := s.Annotations[AnnotationGeneratedAt]; ok {
		t.Error("Secret without autogenerate annotation should not be processed")
	}

	// Check that password was not modified
	if string(s.Data["password"]) != "manual-password" {
		t.Error("Password should not be modified for secrets without annotation")
	}

	t.Log("Secret without annotation correctly not processed")
}

func TestSecretExistingValuePreserved(t *testing.T) {
	defer cleanupSecret(t, "test-existing-value")

	ctx := context.Background()

	// Create a secret with autogenerate annotation but existing password
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-existing-value",
			Namespace: testNamespace,
			Annotations: map[string]string{
				AnnotationAutogenerate: "password,new-field",
				AnnotationType:         "string",
				AnnotationLength:       "32",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"password": []byte("existing-password"),
		},
	}

	_, err := clientset.CoreV1().Secrets(testNamespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Wait for the operator to process the secret
	var processedSecret *corev1.Secret
	err = wait.PollUntilContextTimeout(ctx, pollInterval, pollTimeout, true, func(ctx context.Context) (bool, error) {
		s, err := clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-existing-value", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		// Check if new-field was generated
		if _, ok := s.Data["new-field"]; ok {
			if s.Annotations[AnnotationGeneratedAt] != "" {
				processedSecret = s
				return true, nil
			}
		}
		return false, nil
	})

	if err != nil {
		t.Fatalf("Timeout waiting for secret to be processed: %v", err)
	}

	// Verify existing password was preserved
	if string(processedSecret.Data["password"]) != "existing-password" {
		t.Error("Existing password value should be preserved")
	}

	// Verify new-field was generated
	if len(processedSecret.Data["new-field"]) != 32 {
		t.Error("New field should be generated with specified length")
	}

	t.Log("Existing value correctly preserved, new field generated")
}

func TestSecretFieldSpecificConfig(t *testing.T) {
	defer cleanupSecret(t, "test-field-specific")

	ctx := context.Background()

	// Create a secret with field-specific type and length overrides
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-field-specific",
			Namespace: testNamespace,
			Annotations: map[string]string{
				AnnotationAutogenerate:              "password,encryption-key",
				AnnotationType:                      "string",
				AnnotationLength:                    "24",
				AnnotationTypePrefix + "encryption-key":   "bytes",
				AnnotationLengthPrefix + "encryption-key": "32",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{},
	}

	_, err := clientset.CoreV1().Secrets(testNamespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Wait for the operator to process the secret
	var processedSecret *corev1.Secret
	err = wait.PollUntilContextTimeout(ctx, pollInterval, pollTimeout, true, func(ctx context.Context) (bool, error) {
		s, err := clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-field-specific", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		_, hasPassword := s.Data["password"]
		_, hasEncryptionKey := s.Data["encryption-key"]

		if hasPassword && hasEncryptionKey && s.Annotations[AnnotationGeneratedAt] != "" {
			processedSecret = s
			return true, nil
		}
		return false, nil
	})

	if err != nil {
		t.Fatalf("Timeout waiting for secret to be processed: %v", err)
	}

	// Verify password is a string with length 24
	password := string(processedSecret.Data["password"])
	if len(password) != 24 {
		t.Errorf("Expected password length 24, got %d", len(password))
	}

	// Verify encryption-key is bytes with length 32
	encryptionKey := processedSecret.Data["encryption-key"]
	if len(encryptionKey) != 32 {
		t.Errorf("Expected encryption-key length 32 bytes, got %d", len(encryptionKey))
	}

	t.Log("Field-specific configuration correctly applied")
}
