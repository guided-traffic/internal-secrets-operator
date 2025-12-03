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
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
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
	// AnnotationPrefix is the prefix for all secret generator annotations
	AnnotationPrefix = "secgen.gtrfc.com/"

	// AnnotationAutogenerate specifies which fields to auto-generate
	AnnotationAutogenerate = AnnotationPrefix + "autogenerate"

	// AnnotationType specifies the type of generated value
	AnnotationType = AnnotationPrefix + "type"

	// AnnotationLength specifies the length of the generated value
	AnnotationLength = AnnotationPrefix + "length"

	// AnnotationSecure indicates the value was securely generated
	AnnotationSecure = AnnotationPrefix + "secure"

	// AnnotationGeneratedAt indicates when the value was generated
	AnnotationGeneratedAt = AnnotationPrefix + "generated-at"

	// AnnotationRegenerate forces regeneration of the secret
	AnnotationRegenerate = AnnotationPrefix + "regenerate"

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
	"test-uuid",
	"test-base64",
	"test-regenerate",
	"test-no-annotation",
	"test-existing-value",
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
			// Check if secure annotation was set
			if s.Annotations[AnnotationSecure] == "yes" {
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

		if hasPassword && hasApiKey && hasToken && s.Annotations[AnnotationSecure] == "yes" {
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

func TestSecretUUIDGeneration(t *testing.T) {
	defer cleanupSecret(t, "test-uuid")

	ctx := context.Background()

	// Create a secret with UUID type
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-uuid",
			Namespace: testNamespace,
			Annotations: map[string]string{
				AnnotationAutogenerate: "client-id",
				AnnotationType:         "uuid",
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
		s, err := clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-uuid", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		if _, ok := s.Data["client-id"]; ok {
			if s.Annotations[AnnotationSecure] == "yes" {
				processedSecret = s
				return true, nil
			}
		}
		return false, nil
	})

	if err != nil {
		t.Fatalf("Timeout waiting for secret to be processed: %v", err)
	}

	// Verify the generated UUID format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
	clientID := string(processedSecret.Data["client-id"])
	parts := strings.Split(clientID, "-")
	if len(parts) != 5 {
		t.Errorf("Expected UUID format, got: %s", clientID)
	}
	if len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 || len(parts[3]) != 4 || len(parts[4]) != 12 {
		t.Errorf("Invalid UUID part lengths: %s", clientID)
	}

	t.Logf("UUID successfully generated: %s", clientID)
}

func TestSecretBase64Generation(t *testing.T) {
	defer cleanupSecret(t, "test-base64")

	ctx := context.Background()

	// Create a secret with base64 type
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-base64",
			Namespace: testNamespace,
			Annotations: map[string]string{
				AnnotationAutogenerate: "encryption-key",
				AnnotationType:         "base64",
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
		s, err := clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-base64", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		if _, ok := s.Data["encryption-key"]; ok {
			if s.Annotations[AnnotationSecure] == "yes" {
				processedSecret = s
				return true, nil
			}
		}
		return false, nil
	})

	if err != nil {
		t.Fatalf("Timeout waiting for secret to be processed: %v", err)
	}

	// Verify the generated value is valid base64
	encryptionKey := string(processedSecret.Data["encryption-key"])
	_, err = base64.StdEncoding.DecodeString(encryptionKey)
	if err != nil {
		t.Errorf("Expected valid base64 string, got error: %v", err)
	}

	t.Logf("Base64 key successfully generated with length: %d", len(encryptionKey))
}

func TestSecretRegeneration(t *testing.T) {
	defer cleanupSecret(t, "test-regenerate")

	ctx := context.Background()

	// Create initial secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-regenerate",
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
		s, err := clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-regenerate", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		if pwd, ok := s.Data["password"]; ok {
			if s.Annotations[AnnotationSecure] == "yes" {
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

	// Add regenerate annotation to trigger regeneration
	currentSecret, err := clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-regenerate", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}

	currentSecret.Annotations[AnnotationRegenerate] = "true"
	_, err = clientset.CoreV1().Secrets(testNamespace).Update(ctx, currentSecret, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Failed to update secret with regenerate annotation: %v", err)
	}

	// Wait for regeneration
	var newPassword string
	err = wait.PollUntilContextTimeout(ctx, pollInterval, pollTimeout, true, func(ctx context.Context) (bool, error) {
		s, err := clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-regenerate", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		// Check if regenerate annotation was removed and password changed
		if _, hasRegenerate := s.Annotations[AnnotationRegenerate]; !hasRegenerate {
			pwd := string(s.Data["password"])
			if pwd != originalPassword {
				newPassword = pwd
				return true, nil
			}
		}
		return false, nil
	})

	if err != nil {
		t.Fatalf("Timeout waiting for secret regeneration: %v", err)
	}

	if newPassword == originalPassword {
		t.Error("Expected password to be regenerated with different value")
	}

	t.Logf("Password successfully regenerated: %s...", newPassword[:8])
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
	if _, ok := s.Annotations[AnnotationSecure]; ok {
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
			if s.Annotations[AnnotationSecure] == "yes" {
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
