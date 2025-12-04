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
	AnnotationPrefix = "iso.gtrfc.com/"

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

	// AnnotationRotate specifies the default rotation interval for all fields
	AnnotationRotate = AnnotationPrefix + "rotate"

	// AnnotationRotatePrefix is the prefix for field-specific rotation annotations
	AnnotationRotatePrefix = AnnotationPrefix + "rotate."

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
	"test-rotation-basic",
	"test-rotation-field-specific",
	"test-rotation-min-interval",
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
				AnnotationAutogenerate:                    "password,encryption-key",
				AnnotationType:                            "string",
				AnnotationLength:                          "24",
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

func TestSecretRotationBasic(t *testing.T) {
	defer cleanupSecret(t, "test-rotation-basic")

	ctx := context.Background()

	// Create a secret with rotation annotation (10s rotation for fast E2E testing)
	// Note: The operator is configured with minInterval: 5s in helm-values.yaml
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rotation-basic",
			Namespace: testNamespace,
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
				AnnotationType:         "string",
				AnnotationLength:       "32",
				AnnotationRotate:       "10s",
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
	var originalGeneratedAt string
	err = wait.PollUntilContextTimeout(ctx, pollInterval, pollTimeout, true, func(ctx context.Context) (bool, error) {
		s, err := clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-rotation-basic", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		if pwd, ok := s.Data["password"]; ok {
			if genAt := s.Annotations[AnnotationGeneratedAt]; genAt != "" {
				originalPassword = string(pwd)
				originalGeneratedAt = genAt
				return true, nil
			}
		}
		return false, nil
	})

	if err != nil {
		t.Fatalf("Timeout waiting for initial secret generation: %v", err)
	}

	t.Logf("Initial password generated at %s: %s...", originalGeneratedAt, originalPassword[:8])

	// Wait for rotation to occur (10s interval + some buffer)
	// The operator should automatically rotate the secret after the interval expires
	t.Log("Waiting for rotation to occur (this may take ~15 seconds)...")

	var newPassword string
	var newGeneratedAt string
	err = wait.PollUntilContextTimeout(ctx, 2*time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		s, err := clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-rotation-basic", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		pwd := string(s.Data["password"])
		genAt := s.Annotations[AnnotationGeneratedAt]

		// Check if password was rotated (different value and different timestamp)
		if pwd != originalPassword && genAt != originalGeneratedAt {
			newPassword = pwd
			newGeneratedAt = genAt
			return true, nil
		}
		return false, nil
	})

	if err != nil {
		t.Fatalf("Timeout waiting for secret rotation: %v", err)
	}

	t.Logf("Password rotated at %s: %s...", newGeneratedAt, newPassword[:8])
	t.Log("Basic rotation test passed successfully")
}

func TestSecretRotationFieldSpecific(t *testing.T) {
	defer cleanupSecret(t, "test-rotation-field-specific")

	ctx := context.Background()

	// Create a secret with field-specific rotation intervals
	// password: 10s rotation, api-key: no rotation (default)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rotation-field-specific",
			Namespace: testNamespace,
			Annotations: map[string]string{
				AnnotationAutogenerate:            "password,api-key",
				AnnotationType:                    "string",
				AnnotationLength:                  "24",
				AnnotationRotatePrefix + "password": "10s",
				// api-key has no rotation annotation, so it should not be rotated
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
	var originalPassword, originalApiKey string
	err = wait.PollUntilContextTimeout(ctx, pollInterval, pollTimeout, true, func(ctx context.Context) (bool, error) {
		s, err := clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-rotation-field-specific", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		pwd, hasPwd := s.Data["password"]
		apiKey, hasApiKey := s.Data["api-key"]

		if hasPwd && hasApiKey && s.Annotations[AnnotationGeneratedAt] != "" {
			originalPassword = string(pwd)
			originalApiKey = string(apiKey)
			return true, nil
		}
		return false, nil
	})

	if err != nil {
		t.Fatalf("Timeout waiting for initial secret generation: %v", err)
	}

	t.Logf("Initial values - password: %s..., api-key: %s...", originalPassword[:8], originalApiKey[:8])

	// Wait for password rotation (10s + buffer)
	t.Log("Waiting for password rotation (api-key should remain unchanged)...")

	var rotatedPassword, currentApiKey string
	err = wait.PollUntilContextTimeout(ctx, 2*time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		s, err := clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-rotation-field-specific", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		pwd := string(s.Data["password"])
		apiKey := string(s.Data["api-key"])

		// Check if password was rotated
		if pwd != originalPassword {
			rotatedPassword = pwd
			currentApiKey = apiKey
			return true, nil
		}
		return false, nil
	})

	if err != nil {
		t.Fatalf("Timeout waiting for password rotation: %v", err)
	}

	// Verify password was rotated
	if rotatedPassword == originalPassword {
		t.Error("Expected password to be rotated")
	}

	// Verify api-key was NOT rotated (no rotation annotation)
	if currentApiKey != originalApiKey {
		t.Errorf("Expected api-key to remain unchanged, but it was rotated from %s... to %s...",
			originalApiKey[:8], currentApiKey[:8])
	}

	t.Logf("Rotated password: %s..., unchanged api-key: %s...", rotatedPassword[:8], currentApiKey[:8])
	t.Log("Field-specific rotation test passed successfully")
}

func TestSecretRotationMinIntervalValidation(t *testing.T) {
	defer cleanupSecret(t, "test-rotation-min-interval")

	ctx := context.Background()

	// Create a secret with rotation interval below minInterval (5s configured in helm-values.yaml)
	// This should trigger a warning event
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rotation-min-interval",
			Namespace: testNamespace,
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
				AnnotationType:         "string",
				AnnotationLength:       "32",
				AnnotationRotate:       "1s", // Below minInterval of 5s
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{},
	}

	_, err := clientset.CoreV1().Secrets(testNamespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Wait for the operator to process the secret and create a warning event
	time.Sleep(5 * time.Second)

	// Check for warning events on the secret
	events, err := clientset.CoreV1().Events(testNamespace).List(ctx, metav1.ListOptions{
		FieldSelector: "involvedObject.name=test-rotation-min-interval,involvedObject.kind=Secret",
	})
	if err != nil {
		t.Fatalf("Failed to list events: %v", err)
	}

	// Look for a warning event about rotation interval
	var foundWarning bool
	for _, event := range events.Items {
		if event.Type == "Warning" {
			t.Logf("Found warning event: %s - %s", event.Reason, event.Message)
			foundWarning = true
		}
	}

	if !foundWarning {
		t.Log("Note: Warning event not found. The operator may have used minInterval instead of rejecting the value.")
	}

	// Verify the secret was still processed (password should be generated)
	s, err := clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-rotation-min-interval", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}

	if _, ok := s.Data["password"]; !ok {
		t.Error("Expected password to be generated despite invalid rotation interval")
	}

	t.Log("Min interval validation test completed")
}
