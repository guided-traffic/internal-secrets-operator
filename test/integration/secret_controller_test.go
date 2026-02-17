//go:build integration
// +build integration

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

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/guided-traffic/internal-secrets-operator/pkg/config"
)

const (
	// Annotation constants
	AnnotationPrefix       = "iso.gtrfc.com/"
	AnnotationAutogenerate = AnnotationPrefix + "autogenerate"
	AnnotationType         = AnnotationPrefix + "type"
	AnnotationLength       = AnnotationPrefix + "length"
	AnnotationTypePrefix   = AnnotationPrefix + "type."
	AnnotationLengthPrefix = AnnotationPrefix + "length."
	AnnotationCurve        = AnnotationPrefix + "curve"
	AnnotationCurvePrefix  = AnnotationPrefix + "curve."
	AnnotationGeneratedAt  = AnnotationPrefix + "generated-at"

	// Test timeouts
	timeout  = 10 * time.Second
	interval = 100 * time.Millisecond
)

// waitForSecretField waits for a specific field to be populated in a secret
func waitForSecretField(ctx context.Context, c client.Client, key types.NamespacedName, field string) (*corev1.Secret, error) {
	var secret corev1.Secret
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if err := c.Get(ctx, key, &secret); err != nil {
			time.Sleep(interval)
			continue
		}

		if _, ok := secret.Data[field]; ok {
			return &secret, nil
		}

		time.Sleep(interval)
	}

	// Return whatever we have, even if incomplete
	if err := c.Get(ctx, key, &secret); err != nil {
		return nil, err
	}
	return &secret, nil
}

// waitForAnnotation waits for a specific annotation to be set on a secret
func waitForAnnotation(ctx context.Context, c client.Client, key types.NamespacedName, annotation string) (*corev1.Secret, error) {
	var secret corev1.Secret
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if err := c.Get(ctx, key, &secret); err != nil {
			time.Sleep(interval)
			continue
		}

		if _, ok := secret.Annotations[annotation]; ok {
			return &secret, nil
		}

		time.Sleep(interval)
	}

	// Return whatever we have
	if err := c.Get(ctx, key, &secret); err != nil {
		return nil, err
	}
	return &secret, nil
}

// TestSecretController runs all secret controller integration tests
func TestSecretController(t *testing.T) {
	tc := setupTestManager(t, nil)
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	t.Run("BasicSecretGeneration", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-basic",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate: "password",
				},
			},
			Type: corev1.SecretTypeOpaque,
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
		updatedSecret, err := waitForSecretField(ctx, tc.client, key, "password")
		if err != nil {
			t.Fatalf("failed to get secret: %v", err)
		}

		password, ok := updatedSecret.Data["password"]
		if !ok {
			t.Fatal("expected password field to be generated")
		}

		// Default length should be 32
		if len(password) != 32 {
			t.Errorf("expected password length 32, got %d", len(password))
		}

		if _, ok := updatedSecret.Annotations[AnnotationGeneratedAt]; !ok {
			t.Error("expected generated-at annotation to be set")
		}
	})

	t.Run("MultipleFieldGeneration", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-multi-field",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate: "password,api-key,token",
					AnnotationLength:       "24",
				},
			},
			Type: corev1.SecretTypeOpaque,
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
		updatedSecret, _ := waitForSecretField(ctx, tc.client, key, "password")

		fields := []string{"password", "api-key", "token"}
		for _, field := range fields {
			value, ok := updatedSecret.Data[field]
			if !ok {
				t.Errorf("expected field %q to be generated", field)
				continue
			}
			if len(value) != 24 {
				t.Errorf("expected %s length 24, got %d", field, len(value))
			}
		}

		// Verify all fields are unique
		values := make(map[string]bool)
		for _, field := range fields {
			val := string(updatedSecret.Data[field])
			if values[val] {
				t.Errorf("fields should have unique values, found duplicate")
			}
			values[val] = true
		}
	})

	t.Run("FieldSpecificTypeAndLength", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-field-specific",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate:                    "password,encryption-key",
					AnnotationType:                            "string",
					AnnotationLength:                          "16",
					AnnotationTypePrefix + "encryption-key":   "bytes",
					AnnotationLengthPrefix + "encryption-key": "32",
				},
			},
			Type: corev1.SecretTypeOpaque,
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
		updatedSecret, _ := waitForSecretField(ctx, tc.client, key, "password")

		password := updatedSecret.Data["password"]
		if len(password) != 16 {
			t.Errorf("expected password length 16, got %d", len(password))
		}

		encKey := updatedSecret.Data["encryption-key"]
		if len(encKey) != 32 {
			t.Errorf("expected encryption-key length 32 bytes, got %d", len(encKey))
		}
	})

	t.Run("ExistingValuePreserved", func(t *testing.T) {
		existingPassword := "my-existing-password"
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-preserve",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate: "password,api-key",
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"password": []byte(existingPassword),
			},
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
		updatedSecret, _ := waitForSecretField(ctx, tc.client, key, "api-key")

		if string(updatedSecret.Data["password"]) != existingPassword {
			t.Errorf("existing password was overwritten, expected %q, got %q",
				existingPassword, string(updatedSecret.Data["password"]))
		}

		if _, ok := updatedSecret.Data["api-key"]; !ok {
			t.Error("expected api-key to be generated")
		}
	})

	t.Run("SecretWithoutAnnotationNotProcessed", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-no-annotation",
				Namespace: ns.Name,
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"password": []byte("unchanged"),
			},
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		time.Sleep(2 * time.Second)

		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
		var updatedSecret corev1.Secret
		if err := tc.client.Get(ctx, key, &updatedSecret); err != nil {
			t.Fatalf("failed to get secret: %v", err)
		}

		if _, ok := updatedSecret.Annotations[AnnotationGeneratedAt]; ok {
			t.Error("secret without autogenerate annotation should not have generated-at annotation")
		}

		if string(updatedSecret.Data["password"]) != "unchanged" {
			t.Error("secret data should not be modified")
		}
	})

	t.Run("RegenerationByFieldDeletion", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-regenerate",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate: "password",
				},
			},
			Type: corev1.SecretTypeOpaque,
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
		updatedSecret, _ := waitForSecretField(ctx, tc.client, key, "password")
		originalPassword := string(updatedSecret.Data["password"])

		delete(updatedSecret.Data, "password")
		if err := tc.client.Update(ctx, updatedSecret); err != nil {
			t.Fatalf("failed to update secret: %v", err)
		}

		time.Sleep(1 * time.Second)
		updatedSecret, _ = waitForSecretField(ctx, tc.client, key, "password")
		newPassword := string(updatedSecret.Data["password"])

		if newPassword == originalPassword {
			t.Error("password should be regenerated with a different value")
		}
	})

	t.Run("BytesTypeGeneration", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-bytes",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate: "encryption-key",
					AnnotationType:         "bytes",
					AnnotationLength:       "32",
				},
			},
			Type: corev1.SecretTypeOpaque,
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
		updatedSecret, _ := waitForSecretField(ctx, tc.client, key, "encryption-key")

		encKey := updatedSecret.Data["encryption-key"]
		if len(encKey) != 32 {
			t.Errorf("expected encryption-key length 32 bytes, got %d", len(encKey))
		}
	})

	t.Run("CustomLength", func(t *testing.T) {
		lengthTestCases := []struct {
			name           string
			length         string
			expectedLength int
		}{
			{"length-16", "16", 16},
			{"length-64", "64", 64},
			{"length-128", "128", 128},
		}

		for _, ltc := range lengthTestCases {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ltc.name,
					Namespace: ns.Name,
					Annotations: map[string]string{
						AnnotationAutogenerate: "password",
						AnnotationLength:       ltc.length,
					},
				},
				Type: corev1.SecretTypeOpaque,
			}

			if err := tc.client.Create(ctx, secret); err != nil {
				t.Fatalf("failed to create secret: %v", err)
			}

			key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
			updatedSecret, _ := waitForSecretField(ctx, tc.client, key, "password")

			password := updatedSecret.Data["password"]
			if len(password) != ltc.expectedLength {
				t.Errorf("expected password length %d, got %d", ltc.expectedLength, len(password))
			}
		}
	})

	t.Run("InvalidTypeReturnsError", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-invalid-type",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate: "password",
					AnnotationType:         "invalid-type",
				},
			},
			Type: corev1.SecretTypeOpaque,
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		time.Sleep(2 * time.Second)

		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
		var updatedSecret corev1.Secret
		if err := tc.client.Get(ctx, key, &updatedSecret); err != nil {
			t.Fatalf("failed to get secret: %v", err)
		}

		if _, ok := updatedSecret.Data["password"]; ok {
			t.Error("password should not be generated with invalid type")
		}

		if _, ok := updatedSecret.Annotations[AnnotationGeneratedAt]; ok {
			t.Error("generated-at should not be set when generation fails")
		}
	})

	t.Run("EmptyAutogenerateAnnotation", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-empty-annotation",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate: "",
				},
			},
			Type: corev1.SecretTypeOpaque,
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		time.Sleep(2 * time.Second)

		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
		var updatedSecret corev1.Secret
		if err := tc.client.Get(ctx, key, &updatedSecret); err != nil {
			t.Fatalf("failed to get secret: %v", err)
		}

		if _, ok := updatedSecret.Annotations[AnnotationGeneratedAt]; ok {
			t.Error("generated-at should not be set for empty autogenerate annotation")
		}
	})

	t.Run("FieldsWithWhitespace", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-whitespace",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate: "  password  ,  api-key  ,token  ",
				},
			},
			Type: corev1.SecretTypeOpaque,
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
		updatedSecret, _ := waitForSecretField(ctx, tc.client, key, "password")

		expectedFields := []string{"password", "api-key", "token"}
		for _, field := range expectedFields {
			if _, ok := updatedSecret.Data[field]; !ok {
				t.Errorf("expected field %q to be generated", field)
			}
		}
	})

	t.Run("GeneratedAtTimestamp", func(t *testing.T) {
		// Use truncated time to avoid sub-second precision issues
		beforeCreate := time.Now().Add(-1 * time.Second)

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-timestamp",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate: "password",
				},
			},
			Type: corev1.SecretTypeOpaque,
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
		updatedSecret, _ := waitForAnnotation(ctx, tc.client, key, AnnotationGeneratedAt)

		afterCreate := time.Now().Add(10 * time.Second)

		generatedAt := updatedSecret.Annotations[AnnotationGeneratedAt]
		if generatedAt == "" {
			t.Fatal("expected generated-at annotation to be set")
		}

		timestamp, err := time.Parse(time.RFC3339, generatedAt)
		if err != nil {
			t.Errorf("generated-at timestamp is not valid RFC3339: %q, error: %v", generatedAt, err)
			return
		}

		if timestamp.Before(beforeCreate) || timestamp.After(afterCreate) {
			t.Errorf("generated-at timestamp %v is outside expected range [%v, %v]",
				timestamp, beforeCreate, afterCreate)
		}
	})

	t.Run("MultipleSecretsInNamespace", func(t *testing.T) {
		secrets := []*corev1.Secret{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "secret-a",
					Namespace: ns.Name,
					Annotations: map[string]string{
						AnnotationAutogenerate: "password",
						AnnotationLength:       "16",
					},
				},
				Type: corev1.SecretTypeOpaque,
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "secret-b",
					Namespace: ns.Name,
					Annotations: map[string]string{
						AnnotationAutogenerate: "api-key",
						AnnotationLength:       "24",
					},
				},
				Type: corev1.SecretTypeOpaque,
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "secret-c",
					Namespace: ns.Name,
					Annotations: map[string]string{
						AnnotationAutogenerate: "token",
						AnnotationLength:       "32",
					},
				},
				Type: corev1.SecretTypeOpaque,
			},
		}

		for _, s := range secrets {
			if err := tc.client.Create(ctx, s); err != nil {
				t.Fatalf("failed to create secret %s: %v", s.Name, err)
			}
		}

		testCases := []struct {
			secretName string
			field      string
			length     int
		}{
			{"secret-a", "password", 16},
			{"secret-b", "api-key", 24},
			{"secret-c", "token", 32},
		}

		for _, testCase := range testCases {
			key := types.NamespacedName{Name: testCase.secretName, Namespace: ns.Name}
			updatedSecret, _ := waitForSecretField(ctx, tc.client, key, testCase.field)

			value := updatedSecret.Data[testCase.field]
			if len(value) != testCase.length {
				t.Errorf("secret %s: expected %s length %d, got %d",
					testCase.secretName, testCase.field, testCase.length, len(value))
			}
		}
	})

	t.Run("ConcurrentSecretCreation", func(t *testing.T) {
		numSecrets := 5
		done := make(chan bool, numSecrets)

		for i := 0; i < numSecrets; i++ {
			go func(idx int) {
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "concurrent-" + strings.Repeat(string(rune('a'+idx)), 1),
						Namespace: ns.Name,
						Annotations: map[string]string{
							AnnotationAutogenerate: "password",
						},
					},
					Type: corev1.SecretTypeOpaque,
				}
				tc.client.Create(ctx, secret)
				done <- true
			}(i)
		}

		for i := 0; i < numSecrets; i++ {
			<-done
		}

		time.Sleep(5 * time.Second)

		var secretList corev1.SecretList
		if err := tc.client.List(ctx, &secretList, client.InNamespace(ns.Name)); err != nil {
			t.Fatalf("failed to list secrets: %v", err)
		}

		processedCount := 0
		for _, s := range secretList.Items {
			if strings.HasPrefix(s.Name, "concurrent-") {
				if _, ok := s.Data["password"]; ok {
					processedCount++
				}
			}
		}

		if processedCount < numSecrets {
			t.Errorf("expected at least %d concurrent secrets to be processed, got %d", numSecrets, processedCount)
		}
	})
}

// TestConfigDefaults runs tests that require a custom configuration
func TestConfigDefaults(t *testing.T) {
	customConfig := &config.Config{
		Defaults: config.DefaultsConfig{
			Type:   "string",
			Length: 48,
			String: config.StringOptions{
				Uppercase:    true,
				Lowercase:    true,
				Numbers:      true,
				SpecialChars: false,
			},
		},
	}

	tc := setupTestManager(t, customConfig)
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-defaults",
			Namespace: ns.Name,
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
			},
		},
		Type: corev1.SecretTypeOpaque,
	}

	if err := tc.client.Create(ctx, secret); err != nil {
		t.Fatalf("failed to create secret: %v", err)
	}

	key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
	updatedSecret, _ := waitForSecretField(ctx, tc.client, key, "password")

	password := updatedSecret.Data["password"]
	if len(password) != 48 {
		t.Errorf("expected password length 48 (from config default), got %d", len(password))
	}
}

// TestKeypairGeneration runs integration tests for RSA, ECDSA, and Ed25519 keypair generation
func TestKeypairGeneration(t *testing.T) {
	tc := setupTestManager(t, nil)
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	t.Run("RSAKeypairGeneration", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-rsa-keypair",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate:             "tls-key",
					AnnotationTypePrefix + "tls-key":   "rsa",
					AnnotationLengthPrefix + "tls-key": "2048",
				},
			},
			Type: corev1.SecretTypeOpaque,
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
		updatedSecret, err := waitForSecretField(ctx, tc.client, key, "tls-key")
		if err != nil {
			t.Fatalf("failed to get secret: %v", err)
		}

		// Verify private key
		privateKey, ok := updatedSecret.Data["tls-key"]
		if !ok {
			t.Fatal("expected tls-key field to be generated")
		}
		if !strings.HasPrefix(string(privateKey), "-----BEGIN RSA PRIVATE KEY-----") {
			t.Error("expected RSA private key PEM format")
		}

		// Verify public key
		publicKey, ok := updatedSecret.Data["tls-key.pub"]
		if !ok {
			t.Fatal("expected tls-key.pub field to be generated")
		}
		if !strings.HasPrefix(string(publicKey), "-----BEGIN RSA PUBLIC KEY-----") {
			t.Error("expected RSA public key PEM format")
		}

		if _, ok := updatedSecret.Annotations[AnnotationGeneratedAt]; !ok {
			t.Error("expected generated-at annotation")
		}
	})

	t.Run("ECDSAKeypairGeneration", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-ecdsa-keypair",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate:                 "signing-key",
					AnnotationTypePrefix + "signing-key":   "ecdsa",
					AnnotationCurvePrefix + "signing-key": "P-384",
				},
			},
			Type: corev1.SecretTypeOpaque,
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
		updatedSecret, err := waitForSecretField(ctx, tc.client, key, "signing-key")
		if err != nil {
			t.Fatalf("failed to get secret: %v", err)
		}

		// Verify private key
		privateKey, ok := updatedSecret.Data["signing-key"]
		if !ok {
			t.Fatal("expected signing-key field to be generated")
		}
		if !strings.HasPrefix(string(privateKey), "-----BEGIN EC PRIVATE KEY-----") {
			t.Error("expected EC private key PEM format")
		}

		// Verify public key
		publicKey, ok := updatedSecret.Data["signing-key.pub"]
		if !ok {
			t.Fatal("expected signing-key.pub field to be generated")
		}
		if !strings.HasPrefix(string(publicKey), "-----BEGIN PUBLIC KEY-----") {
			t.Error("expected public key PEM format")
		}
	})

	t.Run("ECDSAKeypairDefaultCurve", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-ecdsa-default-curve",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate:               "signing-key",
					AnnotationTypePrefix + "signing-key": "ecdsa",
					// No curve annotation → default P-256
				},
			},
			Type: corev1.SecretTypeOpaque,
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
		updatedSecret, err := waitForSecretField(ctx, tc.client, key, "signing-key")
		if err != nil {
			t.Fatalf("failed to get secret: %v", err)
		}

		if _, ok := updatedSecret.Data["signing-key"]; !ok {
			t.Fatal("expected signing-key field to be generated")
		}
		if _, ok := updatedSecret.Data["signing-key.pub"]; !ok {
			t.Fatal("expected signing-key.pub field to be generated")
		}
	})

	t.Run("Ed25519KeypairGeneration", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-ed25519-keypair",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate:             "ssh-key",
					AnnotationTypePrefix + "ssh-key": "ed25519",
				},
			},
			Type: corev1.SecretTypeOpaque,
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
		updatedSecret, err := waitForSecretField(ctx, tc.client, key, "ssh-key")
		if err != nil {
			t.Fatalf("failed to get secret: %v", err)
		}

		// Verify private key
		privateKey, ok := updatedSecret.Data["ssh-key"]
		if !ok {
			t.Fatal("expected ssh-key field to be generated")
		}
		if !strings.HasPrefix(string(privateKey), "-----BEGIN PRIVATE KEY-----") {
			t.Error("expected private key PEM format")
		}

		// Verify public key
		publicKey, ok := updatedSecret.Data["ssh-key.pub"]
		if !ok {
			t.Fatal("expected ssh-key.pub field to be generated")
		}
		if !strings.HasPrefix(string(publicKey), "-----BEGIN PUBLIC KEY-----") {
			t.Error("expected public key PEM format")
		}
	})

	t.Run("MixedKeypairAndStringGeneration", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-mixed-keypair",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate:               "password,tls-key,signing-key,ssh-key",
					AnnotationType:                        "string",
					AnnotationLength:                      "24",
					AnnotationTypePrefix + "tls-key":     "rsa",
					AnnotationLengthPrefix + "tls-key":   "2048",
					AnnotationTypePrefix + "signing-key": "ecdsa",
					AnnotationCurvePrefix + "signing-key": "P-256",
					AnnotationTypePrefix + "ssh-key":     "ed25519",
				},
			},
			Type: corev1.SecretTypeOpaque,
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
		updatedSecret, err := waitForSecretField(ctx, tc.client, key, "password")
		if err != nil {
			t.Fatalf("failed to get secret: %v", err)
		}

		// Wait a bit for all fields to be populated
		time.Sleep(2 * time.Second)
		if err := tc.client.Get(ctx, key, updatedSecret); err != nil {
			t.Fatalf("failed to re-fetch secret: %v", err)
		}

		// Verify password (string)
		password, ok := updatedSecret.Data["password"]
		if !ok {
			t.Fatal("expected password field")
		}
		if len(password) != 24 {
			t.Errorf("expected password length 24, got %d", len(password))
		}

		// Verify RSA keypair
		if _, ok := updatedSecret.Data["tls-key"]; !ok {
			t.Fatal("expected tls-key field")
		}
		if _, ok := updatedSecret.Data["tls-key.pub"]; !ok {
			t.Fatal("expected tls-key.pub field")
		}

		// Verify ECDSA keypair
		if _, ok := updatedSecret.Data["signing-key"]; !ok {
			t.Fatal("expected signing-key field")
		}
		if _, ok := updatedSecret.Data["signing-key.pub"]; !ok {
			t.Fatal("expected signing-key.pub field")
		}

		// Verify Ed25519 keypair
		if _, ok := updatedSecret.Data["ssh-key"]; !ok {
			t.Fatal("expected ssh-key field")
		}
		if _, ok := updatedSecret.Data["ssh-key.pub"]; !ok {
			t.Fatal("expected ssh-key.pub field")
		}

		// Verify no .pub for string type
		if _, ok := updatedSecret.Data["password.pub"]; ok {
			t.Error("string type should not generate a .pub field")
		}
	})

	t.Run("KeypairExistingValuePreserved", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-keypair-existing",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate:             "tls-key",
					AnnotationTypePrefix + "tls-key":   "rsa",
					AnnotationLengthPrefix + "tls-key": "2048",
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"tls-key": []byte("existing-private-key"),
			},
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		// Wait for reconciliation
		time.Sleep(3 * time.Second)

		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
		var updatedSecret corev1.Secret
		if err := tc.client.Get(ctx, key, &updatedSecret); err != nil {
			t.Fatalf("failed to get secret: %v", err)
		}

		// Existing value should be preserved
		if string(updatedSecret.Data["tls-key"]) != "existing-private-key" {
			t.Error("expected existing private key to be preserved")
		}

		// No public key should be generated
		if _, ok := updatedSecret.Data["tls-key.pub"]; ok {
			t.Error("expected no public key when private key already exists")
		}
	})
}
