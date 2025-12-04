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
	"regexp"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/guided-traffic/internal-secrets-operator/pkg/config"
)

// TestCharsetUppercaseOnly tests generation with only uppercase letters
func TestCharsetUppercaseOnly(t *testing.T) {
	customConfig := &config.Config{
		Defaults: config.DefaultsConfig{
			Type:   "string",
			Length: 32,
			String: config.StringOptions{
				Uppercase:    true,
				Lowercase:    false,
				Numbers:      false,
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
			Name:      "test-uppercase",
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

	password := string(updatedSecret.Data["password"])

	uppercasePattern := regexp.MustCompile(`^[A-Z]+$`)
	if !uppercasePattern.MatchString(password) {
		t.Errorf("expected only uppercase letters, got %q", password)
	}
}

// TestCharsetLowercaseOnly tests generation with only lowercase letters
func TestCharsetLowercaseOnly(t *testing.T) {
	customConfig := &config.Config{
		Defaults: config.DefaultsConfig{
			Type:   "string",
			Length: 32,
			String: config.StringOptions{
				Uppercase:    false,
				Lowercase:    true,
				Numbers:      false,
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
			Name:      "test-lowercase",
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

	password := string(updatedSecret.Data["password"])

	lowercasePattern := regexp.MustCompile(`^[a-z]+$`)
	if !lowercasePattern.MatchString(password) {
		t.Errorf("expected only lowercase letters, got %q", password)
	}
}

// TestCharsetNumbersOnly tests generation with only numbers
func TestCharsetNumbersOnly(t *testing.T) {
	customConfig := &config.Config{
		Defaults: config.DefaultsConfig{
			Type:   "string",
			Length: 32,
			String: config.StringOptions{
				Uppercase:    false,
				Lowercase:    false,
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
			Name:      "test-numbers",
			Namespace: ns.Name,
			Annotations: map[string]string{
				AnnotationAutogenerate: "pin",
			},
		},
		Type: corev1.SecretTypeOpaque,
	}

	if err := tc.client.Create(ctx, secret); err != nil {
		t.Fatalf("failed to create secret: %v", err)
	}

	key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
	updatedSecret, _ := waitForSecretField(ctx, tc.client, key, "pin")

	pin := string(updatedSecret.Data["pin"])

	numbersPattern := regexp.MustCompile(`^[0-9]+$`)
	if !numbersPattern.MatchString(pin) {
		t.Errorf("expected only numbers, got %q", pin)
	}
}

// TestCharsetAlphanumeric tests generation with alphanumeric characters
func TestCharsetAlphanumeric(t *testing.T) {
	customConfig := &config.Config{
		Defaults: config.DefaultsConfig{
			Type:   "string",
			Length: 64,
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
			Name:      "test-alphanumeric",
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

	password := string(updatedSecret.Data["password"])

	alphanumericPattern := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	if !alphanumericPattern.MatchString(password) {
		t.Errorf("expected only alphanumeric characters, got %q", password)
	}

	specialCharsPattern := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]`)
	if specialCharsPattern.MatchString(password) {
		t.Errorf("expected no special characters, got %q", password)
	}
}

// TestCharsetWithSpecialChars tests generation with special characters included
func TestCharsetWithSpecialChars(t *testing.T) {
	customConfig := &config.Config{
		Defaults: config.DefaultsConfig{
			Type:   "string",
			Length: 128,
			String: config.StringOptions{
				Uppercase:           true,
				Lowercase:           true,
				Numbers:             true,
				SpecialChars:        true,
				AllowedSpecialChars: "!@#$",
			},
		},
	}

	tc := setupTestManager(t, customConfig)
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-special-chars",
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

	password := string(updatedSecret.Data["password"])

	// Verify only allowed characters (alphanumeric + !@#$)
	allowedPattern := regexp.MustCompile(`^[a-zA-Z0-9!@#$]+$`)
	if !allowedPattern.MatchString(password) {
		t.Errorf("expected only allowed characters (alphanumeric + !@#$), got %q", password)
	}
}

// TestCharsetCustomSpecialChars tests generation with custom special characters
func TestCharsetCustomSpecialChars(t *testing.T) {
	customConfig := &config.Config{
		Defaults: config.DefaultsConfig{
			Type:   "string",
			Length: 128,
			String: config.StringOptions{
				Uppercase:           false,
				Lowercase:           false,
				Numbers:             false,
				SpecialChars:        true,
				AllowedSpecialChars: "-_.",
			},
		},
	}

	tc := setupTestManager(t, customConfig)
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-custom-special",
			Namespace: ns.Name,
			Annotations: map[string]string{
				AnnotationAutogenerate: "separator",
			},
		},
		Type: corev1.SecretTypeOpaque,
	}

	if err := tc.client.Create(ctx, secret); err != nil {
		t.Fatalf("failed to create secret: %v", err)
	}

	key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
	updatedSecret, _ := waitForSecretField(ctx, tc.client, key, "separator")

	separator := string(updatedSecret.Data["separator"])

	// Verify only the custom special characters
	customPattern := regexp.MustCompile(`^[-_.]+$`)
	if !customPattern.MatchString(separator) {
		t.Errorf("expected only -_. characters, got %q", separator)
	}
}

// TestCharsetMixedConfig tests complex charset configuration
func TestCharsetMixedConfig(t *testing.T) {
	customConfig := &config.Config{
		Defaults: config.DefaultsConfig{
			Type:   "string",
			Length: 100,
			String: config.StringOptions{
				Uppercase:           true,
				Lowercase:           true,
				Numbers:             false, // No numbers
				SpecialChars:        true,
				AllowedSpecialChars: "+-",
			},
		},
	}

	tc := setupTestManager(t, customConfig)
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mixed",
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

	password := string(updatedSecret.Data["password"])

	// Verify allowed characters (upper + lower + +-)
	allowedPattern := regexp.MustCompile(`^[a-zA-Z+-]+$`)
	if !allowedPattern.MatchString(password) {
		t.Errorf("expected only letters and +-, got %q", password)
	}

	// Verify NO numbers
	numbersPattern := regexp.MustCompile(`[0-9]`)
	if numbersPattern.MatchString(password) {
		t.Errorf("expected no numbers, but found in %q", password)
	}
}

// TestCharsetDefaultAlphanumeric tests the default alphanumeric charset
func TestCharsetDefaultAlphanumeric(t *testing.T) {
	// Use default config (alphanumeric)
	tc := setupTestManager(t, nil)
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-default-charset",
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

	password := string(updatedSecret.Data["password"])

	// Default should be alphanumeric (no special chars)
	alphanumericPattern := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	if !alphanumericPattern.MatchString(password) {
		t.Errorf("default charset should be alphanumeric, got %q", password)
	}
}

// TestLongPassword tests generation of very long passwords
func TestLongPassword(t *testing.T) {
	tc := setupTestManager(t, nil)
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-long-password",
			Namespace: ns.Name,
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
				AnnotationLength:       "1024",
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
	if len(password) != 1024 {
		t.Errorf("expected password length 1024, got %d", len(password))
	}
}

// TestShortPassword tests generation of very short passwords
func TestShortPassword(t *testing.T) {
	tc := setupTestManager(t, nil)
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-short-password",
			Namespace: ns.Name,
			Annotations: map[string]string{
				AnnotationAutogenerate: "password",
				AnnotationLength:       "1",
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
	if len(password) != 1 {
		t.Errorf("expected password length 1, got %d", len(password))
	}
}

// TestSecretTypeOpaque tests that Opaque secrets work correctly
func TestSecretTypeOpaque(t *testing.T) {
	tc := setupTestManager(t, nil)
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-opaque",
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

	if updatedSecret.Type != corev1.SecretTypeOpaque {
		t.Errorf("expected secret type Opaque, got %s", updatedSecret.Type)
	}
}
