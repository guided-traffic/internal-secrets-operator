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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/guided-traffic/internal-secrets-operator/pkg/config"
)

// defaultCharsetConfig returns a config with the documented defaults:
// uppercase=true, lowercase=true, numbers=true, specialChars=false.
// Used by the annotation-driven tests to prove the annotation overrides
// the config defaults — not just the zero-value config.
func defaultCharsetConfig() *config.Config {
	return &config.Config{
		Defaults: config.DefaultsConfig{
			Type:   "string",
			Length: 32,
			String: config.StringOptions{
				Uppercase:           true,
				Lowercase:           true,
				Numbers:             true,
				SpecialChars:        false,
				AllowedSpecialChars: "!@#$%^&*()_+-=[]{}|;:,.<>?",
			},
		},
	}
}

// TestCharsetAnnotationSpecialCharsOnly proves special chars work
// deterministically: with uppercase/lowercase/numbers disabled and only
// specialChars enabled, every character in the generated value MUST be
// from the allowed special-chars set. No probabilistic check, no log
// warning — a single non-special character fails the test.
func TestCharsetAnnotationSpecialCharsOnly(t *testing.T) {
	tc := setupTestManager(t, defaultCharsetConfig())
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()
	allowed := "!@#$%&*"

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-special-only",
			Namespace: ns.Name,
			Annotations: map[string]string{
				AnnotationAutogenerate:              "password",
				AnnotationLength:                    "128",
				AnnotationStringUppercase:           "false",
				AnnotationStringLowercase:           "false",
				AnnotationStringNumbers:             "false",
				AnnotationStringSpecialChars:        "true",
				AnnotationStringAllowedSpecialChars: allowed,
			},
		},
		Type: corev1.SecretTypeOpaque,
	}

	if err := tc.client.Create(ctx, secret); err != nil {
		t.Fatalf("failed to create secret: %v", err)
	}

	key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
	updated, err := waitForSecretField(ctx, tc.client, key, "password")
	if err != nil {
		t.Fatalf("waiting for secret: %v", err)
	}

	password := string(updated.Data["password"])
	if len(password) != 128 {
		t.Fatalf("expected length 128, got %d", len(password))
	}

	for i, ch := range password {
		if !strings.ContainsRune(allowed, ch) {
			t.Fatalf("non-special character %q at position %d in %q (allowed=%q)", ch, i, password, allowed)
		}
	}
}

// TestCharsetAnnotationSpecialCharsAppear proves that when specialChars
// is enabled together with other charsets, at least one special char
// actually appears in the output. Uses length=2048 so the probability
// of a false-negative is below 10^-100 (negligible).
func TestCharsetAnnotationSpecialCharsAppear(t *testing.T) {
	tc := setupTestManager(t, defaultCharsetConfig())
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()
	allowed := "!@#$"

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-special-present",
			Namespace: ns.Name,
			Annotations: map[string]string{
				AnnotationAutogenerate:              "password",
				AnnotationLength:                    "2048",
				AnnotationStringSpecialChars:        "true",
				AnnotationStringAllowedSpecialChars: allowed,
			},
		},
		Type: corev1.SecretTypeOpaque,
	}

	if err := tc.client.Create(ctx, secret); err != nil {
		t.Fatalf("failed to create secret: %v", err)
	}

	key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
	updated, err := waitForSecretField(ctx, tc.client, key, "password")
	if err != nil {
		t.Fatalf("waiting for secret: %v", err)
	}

	password := string(updated.Data["password"])
	if !strings.ContainsAny(password, allowed) {
		t.Fatalf("expected at least one of %q in password (length=%d), got %q", allowed, len(password), password)
	}

	allowedPattern := regexp.MustCompile(`^[a-zA-Z0-9!@#$]+$`)
	if !allowedPattern.MatchString(password) {
		t.Fatalf("password contains disallowed characters: %q", password)
	}
}

// TestCharsetAnnotationCustomAllowedRestrictsSet verifies that
// allowedSpecialChars via annotation restricts the special-char pool:
// disallowed special chars must NOT appear in the output.
func TestCharsetAnnotationCustomAllowedRestrictsSet(t *testing.T) {
	tc := setupTestManager(t, defaultCharsetConfig())
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()
	allowed := "-_."

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-custom-allowed",
			Namespace: ns.Name,
			Annotations: map[string]string{
				AnnotationAutogenerate:              "token",
				AnnotationLength:                    "256",
				AnnotationStringUppercase:           "false",
				AnnotationStringLowercase:           "false",
				AnnotationStringNumbers:             "false",
				AnnotationStringSpecialChars:        "true",
				AnnotationStringAllowedSpecialChars: allowed,
			},
		},
		Type: corev1.SecretTypeOpaque,
	}

	if err := tc.client.Create(ctx, secret); err != nil {
		t.Fatalf("failed to create secret: %v", err)
	}

	key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
	updated, err := waitForSecretField(ctx, tc.client, key, "token")
	if err != nil {
		t.Fatalf("waiting for secret: %v", err)
	}

	token := string(updated.Data["token"])
	for i, ch := range token {
		if !strings.ContainsRune(allowed, ch) {
			t.Fatalf("character %q at position %d not in allowed set %q (token=%q)", ch, i, allowed, token)
		}
	}

	// Disallowed defaults (e.g. !, @, #) must not appear.
	for _, ch := range "!@#$%^&*()" {
		if strings.ContainsRune(token, ch) {
			t.Fatalf("disallowed special character %q leaked into output %q", ch, token)
		}
	}
}

// TestCharsetAnnotationUppercaseOnly drives uppercase-only via annotation
// (overriding config defaults that have all three letter classes on).
func TestCharsetAnnotationUppercaseOnly(t *testing.T) {
	tc := setupTestManager(t, defaultCharsetConfig())
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-anno-upper",
			Namespace: ns.Name,
			Annotations: map[string]string{
				AnnotationAutogenerate:    "password",
				AnnotationLength:          "64",
				AnnotationStringUppercase: "true",
				AnnotationStringLowercase: "false",
				AnnotationStringNumbers:   "false",
			},
		},
		Type: corev1.SecretTypeOpaque,
	}

	if err := tc.client.Create(ctx, secret); err != nil {
		t.Fatalf("failed to create secret: %v", err)
	}

	key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
	updated, err := waitForSecretField(ctx, tc.client, key, "password")
	if err != nil {
		t.Fatalf("waiting for secret: %v", err)
	}

	password := string(updated.Data["password"])
	if !regexp.MustCompile(`^[A-Z]+$`).MatchString(password) {
		t.Fatalf("expected only uppercase, got %q", password)
	}
}

// TestCharsetAnnotationLowercaseOnly drives lowercase-only via annotation.
func TestCharsetAnnotationLowercaseOnly(t *testing.T) {
	tc := setupTestManager(t, defaultCharsetConfig())
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-anno-lower",
			Namespace: ns.Name,
			Annotations: map[string]string{
				AnnotationAutogenerate:    "password",
				AnnotationLength:          "64",
				AnnotationStringUppercase: "false",
				AnnotationStringLowercase: "true",
				AnnotationStringNumbers:   "false",
			},
		},
		Type: corev1.SecretTypeOpaque,
	}

	if err := tc.client.Create(ctx, secret); err != nil {
		t.Fatalf("failed to create secret: %v", err)
	}

	key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
	updated, err := waitForSecretField(ctx, tc.client, key, "password")
	if err != nil {
		t.Fatalf("waiting for secret: %v", err)
	}

	password := string(updated.Data["password"])
	if !regexp.MustCompile(`^[a-z]+$`).MatchString(password) {
		t.Fatalf("expected only lowercase, got %q", password)
	}
}

// TestCharsetAnnotationNumbersOnly drives numbers-only via annotation
// (matches the README "Numbers-Only PIN" example).
func TestCharsetAnnotationNumbersOnly(t *testing.T) {
	tc := setupTestManager(t, defaultCharsetConfig())
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-anno-pin",
			Namespace: ns.Name,
			Annotations: map[string]string{
				AnnotationAutogenerate:    "pin",
				AnnotationLength:          "6",
				AnnotationStringUppercase: "false",
				AnnotationStringLowercase: "false",
				AnnotationStringNumbers:   "true",
			},
		},
		Type: corev1.SecretTypeOpaque,
	}

	if err := tc.client.Create(ctx, secret); err != nil {
		t.Fatalf("failed to create secret: %v", err)
	}

	key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
	updated, err := waitForSecretField(ctx, tc.client, key, "pin")
	if err != nil {
		t.Fatalf("waiting for secret: %v", err)
	}

	pin := string(updated.Data["pin"])
	if len(pin) != 6 {
		t.Fatalf("expected pin length 6, got %d", len(pin))
	}
	if !regexp.MustCompile(`^[0-9]+$`).MatchString(pin) {
		t.Fatalf("expected only digits, got %q", pin)
	}
}

// TestCharsetAnnotationBoolValueForms verifies the boolean parsing accepts
// "true"/"false" and "1"/"0" forms equivalently for string.* annotations.
func TestCharsetAnnotationBoolValueForms(t *testing.T) {
	tests := []struct {
		name           string
		uppercaseVal   string
		lowercaseVal   string
		numbersVal     string
		expectPattern  string
	}{
		{"string-true-false", "true", "false", "false", `^[A-Z]+$`},
		{"numeric-1-0", "1", "0", "0", `^[A-Z]+$`},
		{"mixed", "TRUE", "0", "false", `^[A-Z]+$`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := setupTestManager(t, defaultCharsetConfig())
			ns := createNamespace(t, tc.client)
			defer tc.cleanup(t, ns)

			ctx := context.Background()

			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-bool-" + tt.name,
					Namespace: ns.Name,
					Annotations: map[string]string{
						AnnotationAutogenerate:    "password",
						AnnotationLength:          "32",
						AnnotationStringUppercase: tt.uppercaseVal,
						AnnotationStringLowercase: tt.lowercaseVal,
						AnnotationStringNumbers:   tt.numbersVal,
					},
				},
				Type: corev1.SecretTypeOpaque,
			}

			if err := tc.client.Create(ctx, secret); err != nil {
				t.Fatalf("failed to create secret: %v", err)
			}

			key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
			updated, err := waitForSecretField(ctx, tc.client, key, "password")
			if err != nil {
				t.Fatalf("waiting for secret: %v", err)
			}

			password := string(updated.Data["password"])
			if !regexp.MustCompile(tt.expectPattern).MatchString(password) {
				t.Fatalf("expected match %q, got %q", tt.expectPattern, password)
			}
		})
	}
}

// TestCharsetAnnotationInvalid_NoCharset verifies that disabling every
// charset via annotation does NOT modify the Secret (validation fails
// before generation, per the documented "user changes preserved" behavior).
func TestCharsetAnnotationInvalid_NoCharset(t *testing.T) {
	tc := setupTestManager(t, defaultCharsetConfig())
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-anno-invalid",
			Namespace: ns.Name,
			Annotations: map[string]string{
				AnnotationAutogenerate:       "password",
				AnnotationStringUppercase:    "false",
				AnnotationStringLowercase:    "false",
				AnnotationStringNumbers:      "false",
				AnnotationStringSpecialChars: "false",
			},
		},
		Type: corev1.SecretTypeOpaque,
	}

	if err := tc.client.Create(ctx, secret); err != nil {
		t.Fatalf("failed to create secret: %v", err)
	}

	// Give the controller time to reconcile (and fail).
	time.Sleep(2 * time.Second)

	var got corev1.Secret
	if err := tc.client.Get(ctx, types.NamespacedName{Name: secret.Name, Namespace: ns.Name}, &got); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if _, ok := got.Data["password"]; ok {
		t.Fatalf("password must NOT be generated when no charset enabled, got %q", got.Data["password"])
	}
}

// TestCharsetAnnotationInvalid_EmptyAllowedSpecialChars verifies that
// enabling specialChars with an explicitly empty allowedSpecialChars
// annotation does NOT generate a value.
func TestCharsetAnnotationInvalid_EmptyAllowedSpecialChars(t *testing.T) {
	tc := setupTestManager(t, defaultCharsetConfig())
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-anno-empty-allowed",
			Namespace: ns.Name,
			Annotations: map[string]string{
				AnnotationAutogenerate:              "password",
				AnnotationStringUppercase:           "false",
				AnnotationStringLowercase:           "false",
				AnnotationStringNumbers:             "false",
				AnnotationStringSpecialChars:        "true",
				AnnotationStringAllowedSpecialChars: "",
			},
		},
		Type: corev1.SecretTypeOpaque,
	}

	if err := tc.client.Create(ctx, secret); err != nil {
		t.Fatalf("failed to create secret: %v", err)
	}

	time.Sleep(2 * time.Second)

	var got corev1.Secret
	if err := tc.client.Get(ctx, types.NamespacedName{Name: secret.Name, Namespace: ns.Name}, &got); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if _, ok := got.Data["password"]; ok {
		t.Fatalf("password must NOT be generated when allowedSpecialChars is empty, got %q", got.Data["password"])
	}
}

// TestCharsetAnnotationOverridesConfigSpecialChars proves that annotation
// values take precedence over config defaults: config says specialChars=false,
// annotation says true with a restricted set — output must contain a special.
func TestCharsetAnnotationOverridesConfigSpecialChars(t *testing.T) {
	cfg := defaultCharsetConfig() // specialChars=false
	tc := setupTestManager(t, cfg)
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()
	allowed := "!@"

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-anno-override",
			Namespace: ns.Name,
			Annotations: map[string]string{
				AnnotationAutogenerate:              "password",
				AnnotationLength:                    "512",
				AnnotationStringSpecialChars:        "true",
				AnnotationStringAllowedSpecialChars: allowed,
			},
		},
		Type: corev1.SecretTypeOpaque,
	}

	if err := tc.client.Create(ctx, secret); err != nil {
		t.Fatalf("failed to create secret: %v", err)
	}

	key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
	updated, err := waitForSecretField(ctx, tc.client, key, "password")
	if err != nil {
		t.Fatalf("waiting for secret: %v", err)
	}

	password := string(updated.Data["password"])
	if !strings.ContainsAny(password, allowed) {
		t.Fatalf("annotation override failed: expected one of %q in %q", allowed, password)
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9!@]+$`).MatchString(password) {
		t.Fatalf("disallowed character in output: %q", password)
	}
}
