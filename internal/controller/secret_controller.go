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
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/guided-traffic/internal-secrets-operator/pkg/config"
	"github.com/guided-traffic/internal-secrets-operator/pkg/generator"
)

const (
	// AnnotationPrefix is the prefix for all secret operator annotations
	AnnotationPrefix = "iso.gtrfc.com/"

	// AnnotationAutogenerate specifies which fields to auto-generate
	AnnotationAutogenerate = AnnotationPrefix + "autogenerate"

	// AnnotationType specifies the default type of generated value (string, bytes)
	AnnotationType = AnnotationPrefix + "type"

	// AnnotationLength specifies the default length of the generated value
	AnnotationLength = AnnotationPrefix + "length"

	// AnnotationTypePrefix is the prefix for field-specific type annotations (type.<field>)
	AnnotationTypePrefix = AnnotationPrefix + "type."

	// AnnotationLengthPrefix is the prefix for field-specific length annotations (length.<field>)
	AnnotationLengthPrefix = AnnotationPrefix + "length."

	// AnnotationGeneratedAt indicates when the value was generated
	AnnotationGeneratedAt = AnnotationPrefix + "generated-at"

	// AnnotationRotate specifies the default rotation interval for all fields
	AnnotationRotate = AnnotationPrefix + "rotate"

	// AnnotationRotatePrefix is the prefix for field-specific rotation annotations (rotate.<field>)
	AnnotationRotatePrefix = AnnotationPrefix + "rotate."

	// Event reasons
	EventReasonGenerationFailed    = "GenerationFailed"
	EventReasonGenerationSucceeded = "GenerationSucceeded"
	EventReasonRotationSucceeded   = "RotationSucceeded"
	EventReasonRotationFailed      = "RotationFailed"
)

// SecretReconciler reconciles a Secret object
type SecretReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Generator     generator.Generator
	Config        *config.Config
	EventRecorder record.EventRecorder
	// Clock is used to get the current time. If nil, time.Now() is used.
	// This allows for time mocking in tests.
	Clock Clock
}

// Clock is an interface for getting the current time.
// This allows for time mocking in tests.
type Clock interface {
	Now() time.Time
}

// RealClock implements Clock using the real time.
type RealClock struct{}

// Now returns the current time.
func (RealClock) Now() time.Time {
	return time.Now()
}

// now returns the current time using the Clock if set, otherwise time.Now()
func (r *SecretReconciler) now() time.Time {
	if r.Clock != nil {
		return r.Clock.Now()
	}
	return time.Now()
}

// since returns the time elapsed since t using the Clock
func (r *SecretReconciler) since(t time.Time) time.Duration {
	return r.now().Sub(t)
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles the reconciliation of Secrets with autogenerate annotations
func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the Secret
	var secret corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &secret); err != nil {
		// Secret was deleted, nothing to do
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check if the secret has the autogenerate annotation
	autogenerate, ok := secret.Annotations[AnnotationAutogenerate]
	if !ok || autogenerate == "" {
		return ctrl.Result{}, nil
	}

	logger.Info("Reconciling Secret", "name", secret.Name, "namespace", secret.Namespace)

	// Parse the fields to generate
	fields := parseFields(autogenerate)
	if len(fields) == 0 {
		logger.Info("No fields to generate")
		return ctrl.Result{}, nil
	}

	// Initialize data map if nil
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}

	// Track if any changes were made
	changed := false
	rotated := false

	// Get the generated-at timestamp for rotation checks
	generatedAt := r.getGeneratedAtTime(secret.Annotations)

	// Calculate next requeue time for rotation
	var nextRotation *time.Duration

	// Generate values for each field
	for _, field := range fields {
		// Get field-specific rotation interval
		rotationInterval := r.getFieldRotationInterval(secret.Annotations, field)

		// Check if rotation is needed
		needsRotation := false
		if rotationInterval > 0 && generatedAt != nil {
			// Validate rotation interval against minInterval
			if rotationInterval < r.Config.Rotation.MinInterval.Duration() {
				errMsg := fmt.Sprintf("Rotation interval %s for field %q is below minimum %s",
					rotationInterval, field, r.Config.Rotation.MinInterval.Duration())
				logger.Error(nil, errMsg, "field", field)
				r.EventRecorder.Event(&secret, corev1.EventTypeWarning, EventReasonRotationFailed, errMsg)
				// Skip rotation for this field, but continue processing
				continue
			}

			timeSinceGeneration := r.since(*generatedAt)
			if timeSinceGeneration >= rotationInterval {
				needsRotation = true
				logger.Info("Field needs rotation", "field", field, "timeSinceGeneration", timeSinceGeneration, "rotationInterval", rotationInterval)
			} else {
				// Calculate time until next rotation
				timeUntilRotation := rotationInterval - timeSinceGeneration
				if nextRotation == nil || timeUntilRotation < *nextRotation {
					nextRotation = &timeUntilRotation
				}
			}
		} else if rotationInterval > 0 && generatedAt == nil {
			// If rotation is configured but no generated-at timestamp exists,
			// we need to calculate the next rotation based on when we generate now
			if nextRotation == nil || rotationInterval < *nextRotation {
				nextRotation = &rotationInterval
			}
		}

		// Skip if field already has a value and doesn't need rotation
		if _, exists := secret.Data[field]; exists && !needsRotation {
			logger.V(1).Info("Field already has value, skipping", "field", field)
			continue
		}

		// Get field-specific generation parameters
		genType := r.getFieldType(secret.Annotations, field)
		length := r.getFieldLength(secret.Annotations, field)

		// Generate the value
		value, err := r.Generator.Generate(genType, length)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to generate value for field %q: %v", field, err)
			logger.Error(err, "Failed to generate value", "field", field, "type", genType)
			r.EventRecorder.Event(&secret, corev1.EventTypeWarning, EventReasonGenerationFailed, errMsg)
			return ctrl.Result{}, fmt.Errorf("failed to generate value for field %s: %w", field, err)
		}

		// Store the value as raw bytes - Kubernetes will handle base64 encoding
		// when storing in etcd and displaying via kubectl
		secret.Data[field] = []byte(value)
		changed = true
		if needsRotation {
			rotated = true
			logger.Info("Rotated value for field", "field", field, "type", genType, "length", length)
		} else {
			logger.Info("Generated value for field", "field", field, "type", genType, "length", length)
		}
	}

	// If changes were made, update the secret
	if changed {
		// Update metadata annotations
		if secret.Annotations == nil {
			secret.Annotations = make(map[string]string)
		}
		secret.Annotations[AnnotationGeneratedAt] = r.now().Format(time.RFC3339)

		// Update the secret
		if err := r.Update(ctx, &secret); err != nil {
			logger.Error(err, "Failed to update Secret")
			return ctrl.Result{}, err
		}

		// Emit success event
		if rotated {
			if r.Config.Rotation.CreateEvents {
				r.EventRecorder.Event(&secret, corev1.EventTypeNormal, EventReasonRotationSucceeded,
					"Successfully rotated values for secret fields")
			}
			logger.Info("Successfully rotated Secret values")
		} else {
			r.EventRecorder.Event(&secret, corev1.EventTypeNormal, EventReasonGenerationSucceeded,
				"Successfully generated values for secret fields")
			logger.Info("Successfully updated Secret with generated values")
		}

		// After generating/rotating, recalculate next rotation time
		// Since we just updated, the next rotation will be the minimum rotation interval
		for _, field := range fields {
			rotationInterval := r.getFieldRotationInterval(secret.Annotations, field)
			if rotationInterval > 0 {
				if nextRotation == nil || rotationInterval < *nextRotation {
					nextRotation = &rotationInterval
				}
			}
		}
	}

	// Return with RequeueAfter if rotation is configured
	if nextRotation != nil {
		logger.Info("Scheduling next reconciliation for rotation", "requeueAfter", *nextRotation)
		return ctrl.Result{RequeueAfter: *nextRotation}, nil
	}

	return ctrl.Result{}, nil
}

// parseFields parses a comma-separated list of field names
func parseFields(value string) []string {
	var fields []string
	for _, field := range strings.Split(value, ",") {
		field = strings.TrimSpace(field)
		if field != "" {
			fields = append(fields, field)
		}
	}
	return fields
}

// getAnnotationOrDefault returns the annotation value or a default
func (r *SecretReconciler) getAnnotationOrDefault(annotations map[string]string, key, defaultValue string) string {
	if value, ok := annotations[key]; ok && value != "" {
		return value
	}
	return defaultValue
}

// getLengthAnnotation returns the length annotation value or the default from config
func (r *SecretReconciler) getLengthAnnotation(annotations map[string]string) int {
	if value, ok := annotations[AnnotationLength]; ok && value != "" {
		if length, err := strconv.Atoi(value); err == nil && length > 0 {
			return length
		}
	}
	return r.Config.Defaults.Length
}

// getFieldType returns the type for a specific field.
// Priority: type.<field> annotation > type annotation > default type from config
func (r *SecretReconciler) getFieldType(annotations map[string]string, field string) string {
	// Check for field-specific type annotation
	fieldTypeKey := AnnotationTypePrefix + field
	if value, ok := annotations[fieldTypeKey]; ok && value != "" {
		return value
	}
	// Fall back to default type annotation
	return r.getAnnotationOrDefault(annotations, AnnotationType, r.Config.Defaults.Type)
}

// getFieldLength returns the length for a specific field.
// Priority: length.<field> annotation > length annotation > default length
func (r *SecretReconciler) getFieldLength(annotations map[string]string, field string) int {
	// Check for field-specific length annotation
	fieldLengthKey := AnnotationLengthPrefix + field
	if value, ok := annotations[fieldLengthKey]; ok && value != "" {
		if length, err := strconv.Atoi(value); err == nil && length > 0 {
			return length
		}
	}
	// Fall back to default length annotation
	return r.getLengthAnnotation(annotations)
}

// getFieldRotationInterval returns the rotation interval for a specific field.
// Priority: rotate.<field> annotation > rotate annotation > 0 (no rotation)
func (r *SecretReconciler) getFieldRotationInterval(annotations map[string]string, field string) time.Duration {
	// Check for field-specific rotation annotation
	fieldRotateKey := AnnotationRotatePrefix + field
	if value, ok := annotations[fieldRotateKey]; ok && value != "" {
		if duration, err := config.ParseDuration(value); err == nil {
			return duration
		}
	}
	// Check for default rotation annotation
	if value, ok := annotations[AnnotationRotate]; ok && value != "" {
		if duration, err := config.ParseDuration(value); err == nil {
			return duration
		}
	}
	// No rotation configured
	return 0
}

// getGeneratedAtTime parses the generated-at annotation and returns the time
func (r *SecretReconciler) getGeneratedAtTime(annotations map[string]string) *time.Time {
	if value, ok := annotations[AnnotationGeneratedAt]; ok && value != "" {
		if t, err := time.Parse(time.RFC3339, value); err == nil {
			return &t
		}
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager
func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Create a predicate that filters secrets with the autogenerate annotation
	hasAutogenerateAnnotation := predicate.NewPredicateFuncs(func(object client.Object) bool {
		annotations := object.GetAnnotations()
		if annotations == nil {
			return false
		}
		_, ok := annotations[AnnotationAutogenerate]
		return ok
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		WithEventFilter(hasAutogenerateAnnotation).
		Complete(r)
}
