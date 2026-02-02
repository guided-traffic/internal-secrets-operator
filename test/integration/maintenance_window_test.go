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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/guided-traffic/internal-secrets-operator/pkg/config"
)

// TestMaintenanceWindowRotationDeferred tests that rotation is deferred outside maintenance windows
func TestMaintenanceWindowRotationDeferred(t *testing.T) {
	// Set up a time that is outside the maintenance window
	// Monday 12:00 UTC - maintenance window is only on weekends
	mockTime := time.Date(2026, 2, 2, 12, 0, 0, 0, time.UTC)
	mockClock := &MockClock{currentTime: mockTime}

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

	tc := setupTestManagerWithClock(t, cfg, mockClock)
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	t.Run("RotationDeferredOutsideWindow", func(t *testing.T) {
		// Create a secret that was generated 2 hours ago and needs rotation
		generatedAt := mockTime.Add(-2 * time.Hour)

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-deferred-rotation",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate: "password",
					AnnotationRotate:       "1h", // Rotation due
					AnnotationGeneratedAt:  generatedAt.Format(time.RFC3339),
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"password": []byte("old-password-value"),
			},
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		// Wait a bit for reconciliation
		time.Sleep(500 * time.Millisecond)

		// Get the secret
		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
		var updatedSecret corev1.Secret
		if err := tc.client.Get(ctx, key, &updatedSecret); err != nil {
			t.Fatalf("failed to get secret: %v", err)
		}

		// Password should NOT have changed (rotation deferred)
		if string(updatedSecret.Data["password"]) != "old-password-value" {
			t.Errorf("expected password to remain unchanged, got: %s", string(updatedSecret.Data["password"]))
		}

		// generated-at should NOT have been updated
		if updatedSecret.Annotations[AnnotationGeneratedAt] != generatedAt.Format(time.RFC3339) {
			t.Error("expected generated-at annotation to remain unchanged")
		}
	})
}

// TestMaintenanceWindowRotationAllowed tests that rotation proceeds inside maintenance windows
func TestMaintenanceWindowRotationAllowed(t *testing.T) {
	// Set up a time that is inside the maintenance window
	// Saturday 04:00 UTC - inside weekend window
	mockTime := time.Date(2026, 2, 7, 4, 0, 0, 0, time.UTC)
	mockClock := &MockClock{currentTime: mockTime}

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

	tc := setupTestManagerWithClock(t, cfg, mockClock)
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	t.Run("RotationProceedsInsideWindow", func(t *testing.T) {
		// Create a secret that was generated 2 hours ago and needs rotation
		generatedAt := mockTime.Add(-2 * time.Hour)

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-allowed-rotation",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate: "password",
					AnnotationRotate:       "1h", // Rotation due
					AnnotationGeneratedAt:  generatedAt.Format(time.RFC3339),
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"password": []byte("old-password-value"),
			},
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		// Wait for reconciliation
		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}

		// Poll until password changes
		var updatedSecret corev1.Secret
		deadline := time.Now().Add(5 * time.Second)
		rotated := false
		for time.Now().Before(deadline) {
			if err := tc.client.Get(ctx, key, &updatedSecret); err == nil {
				if string(updatedSecret.Data["password"]) != "old-password-value" {
					rotated = true
					break
				}
			}
			time.Sleep(100 * time.Millisecond)
		}

		if !rotated {
			t.Error("expected password to be rotated when inside maintenance window")
		}
	})
}

// TestMaintenanceWindowDisabled tests that rotation proceeds when maintenance windows are disabled
func TestMaintenanceWindowDisabled(t *testing.T) {
	// Set up a time that would be outside maintenance window if it was enabled
	mockTime := time.Date(2026, 2, 2, 12, 0, 0, 0, time.UTC)
	mockClock := &MockClock{currentTime: mockTime}

	cfg := config.NewDefaultConfig()
	cfg.Rotation.MaintenanceWindows = config.MaintenanceWindowsConfig{
		Enabled: false, // Disabled
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

	tc := setupTestManagerWithClock(t, cfg, mockClock)
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	t.Run("RotationProceedsWhenDisabled", func(t *testing.T) {
		// Create a secret that was generated 2 hours ago and needs rotation
		generatedAt := mockTime.Add(-2 * time.Hour)

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-disabled-window",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate: "password",
					AnnotationRotate:       "1h", // Rotation due
					AnnotationGeneratedAt:  generatedAt.Format(time.RFC3339),
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"password": []byte("old-password-value"),
			},
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		// Wait for reconciliation
		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}

		// Poll until password changes
		var updatedSecret corev1.Secret
		deadline := time.Now().Add(5 * time.Second)
		rotated := false
		for time.Now().Before(deadline) {
			if err := tc.client.Get(ctx, key, &updatedSecret); err == nil {
				if string(updatedSecret.Data["password"]) != "old-password-value" {
					rotated = true
					break
				}
			}
			time.Sleep(100 * time.Millisecond)
		}

		if !rotated {
			t.Error("expected password to be rotated when maintenance windows are disabled")
		}
	})
}

// TestMaintenanceWindowMultipleWindows tests that the controller uses multiple windows correctly
func TestMaintenanceWindowMultipleWindows(t *testing.T) {
	// Wednesday 03:00 UTC - inside the weekday window
	mockTime := time.Date(2026, 2, 4, 3, 0, 0, 0, time.UTC)
	mockClock := &MockClock{currentTime: mockTime}

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
			{
				Name:      "weekday-maintenance",
				Days:      []string{"wednesday"},
				StartTime: "02:00",
				EndTime:   "04:00",
				Timezone:  "UTC",
			},
		},
	}

	tc := setupTestManagerWithClock(t, cfg, mockClock)
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	t.Run("RotationProceedsInSecondWindow", func(t *testing.T) {
		// Create a secret that was generated 2 hours ago and needs rotation
		generatedAt := mockTime.Add(-2 * time.Hour)

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-multi-window",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate: "password",
					AnnotationRotate:       "1h", // Rotation due
					AnnotationGeneratedAt:  generatedAt.Format(time.RFC3339),
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"password": []byte("old-password-value"),
			},
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		// Wait for reconciliation
		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}

		// Poll until password changes
		var updatedSecret corev1.Secret
		deadline := time.Now().Add(5 * time.Second)
		rotated := false
		for time.Now().Before(deadline) {
			if err := tc.client.Get(ctx, key, &updatedSecret); err == nil {
				if string(updatedSecret.Data["password"]) != "old-password-value" {
					rotated = true
					break
				}
			}
			time.Sleep(100 * time.Millisecond)
		}

		if !rotated {
			t.Error("expected password to be rotated when inside the Wednesday maintenance window")
		}
	})
}

// TestMaintenanceWindowInitialGenerationNotAffected tests that initial generation is not affected
func TestMaintenanceWindowInitialGenerationNotAffected(t *testing.T) {
	// Monday 12:00 UTC - outside maintenance window
	mockTime := time.Date(2026, 2, 2, 12, 0, 0, 0, time.UTC)
	mockClock := &MockClock{currentTime: mockTime}

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

	tc := setupTestManagerWithClock(t, cfg, mockClock)
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	t.Run("InitialGenerationProceeds", func(t *testing.T) {
		// Create a new secret without any existing data - should be generated immediately
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-initial-generation",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate: "password",
					AnnotationRotate:       "1h",
				},
			},
			Type: corev1.SecretTypeOpaque,
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		// Wait for the password field to be generated
		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}
		updatedSecret, err := waitForSecretField(ctx, tc.client, key, "password")
		if err != nil {
			t.Fatalf("failed to get secret with password: %v", err)
		}

		// Password should have been generated even though we're outside maintenance window
		if _, ok := updatedSecret.Data["password"]; !ok {
			t.Error("expected password to be generated even outside maintenance window (initial generation)")
		}
	})
}

// TestMaintenanceWindowDifferentTimezones tests timezone handling
func TestMaintenanceWindowDifferentTimezones(t *testing.T) {
	// 10:00 UTC = 11:00 Berlin (CET in winter)
	// So if we have a Berlin window from 10:00-12:00, it should match
	mockTime := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC) // Saturday 10:00 UTC
	mockClock := &MockClock{currentTime: mockTime}

	cfg := config.NewDefaultConfig()
	cfg.Rotation.MaintenanceWindows = config.MaintenanceWindowsConfig{
		Enabled: true,
		Windows: []config.MaintenanceWindow{
			{
				Name:      "berlin-morning",
				Days:      []string{"saturday"},
				StartTime: "10:00", // 10:00 Berlin = 09:00 UTC
				EndTime:   "12:00", // 12:00 Berlin = 11:00 UTC
				Timezone:  "Europe/Berlin",
			},
		},
	}

	tc := setupTestManagerWithClock(t, cfg, mockClock)
	ns := createNamespace(t, tc.client)
	defer tc.cleanup(t, ns)

	ctx := context.Background()

	t.Run("TimezoneConversionWorks", func(t *testing.T) {
		// Create a secret that was generated 2 hours ago and needs rotation
		generatedAt := mockTime.Add(-2 * time.Hour)

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-timezone",
				Namespace: ns.Name,
				Annotations: map[string]string{
					AnnotationAutogenerate: "password",
					AnnotationRotate:       "1h",
					AnnotationGeneratedAt:  generatedAt.Format(time.RFC3339),
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"password": []byte("old-password-value"),
			},
		}

		if err := tc.client.Create(ctx, secret); err != nil {
			t.Fatalf("failed to create secret: %v", err)
		}

		// Wait for reconciliation
		key := types.NamespacedName{Name: secret.Name, Namespace: ns.Name}

		// Poll until password changes
		var updatedSecret corev1.Secret
		deadline := time.Now().Add(5 * time.Second)
		rotated := false
		for time.Now().Before(deadline) {
			if err := tc.client.Get(ctx, key, &updatedSecret); err == nil {
				if string(updatedSecret.Data["password"]) != "old-password-value" {
					rotated = true
					break
				}
			}
			time.Sleep(100 * time.Millisecond)
		}

		// 10:00 UTC = 11:00 Berlin, which is inside the 10:00-12:00 Berlin window
		if !rotated {
			t.Error("expected password to be rotated (10:00 UTC = 11:00 Berlin, inside 10:00-12:00 window)")
		}
	})
}
