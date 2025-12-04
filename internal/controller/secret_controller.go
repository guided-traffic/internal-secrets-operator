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

	"github.com/go-logr/logr"
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

	// Parse the autogenerate annotation
	fields := parseSecretAnnotations(secret.Annotations)
	if len(fields) == 0 {
		return ctrl.Result{}, nil
	}

	logger.Info("Reconciling Secret", "name", secret.Name, "namespace", secret.Namespace)

	// Initialize data map if nil
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}

	// Get the generated-at timestamp for rotation checks
	generatedAt := r.getGeneratedAtTime(secret.Annotations)

	// Process all fields
	updateResult := r.processSecretFields(&secret, fields, generatedAt, logger)
	if updateResult.skipRest {
		return ctrl.Result{}, updateResult.err
	}

	// If changes were made, update the secret
	if updateResult.changed {
		if err := r.updateSecretAndEmitEvents(ctx, &secret, updateResult.rotated, logger); err != nil {
			return ctrl.Result{}, err
		}
		// Update generatedAt for next rotation calculation
		generatedAt = r.getGeneratedAtTime(secret.Annotations)
	}

	// Calculate next rotation time and schedule requeue if needed
	if nextRotation := r.calculateNextRotation(secret.Annotations, fields, generatedAt); nextRotation != nil {
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

// secretUpdateResult contains the result of updating a secret
type secretUpdateResult struct {
	changed  bool
	rotated  bool
	err      error
	skipRest bool
}

// processSecretFields processes all fields that need generation or rotation.
// It returns the update result indicating what changes were made.
func (r *SecretReconciler) processSecretFields(
	secret *corev1.Secret,
	fields []string,
	generatedAt *time.Time,
	logger logr.Logger,
) secretUpdateResult {
	result := secretUpdateResult{}

	for _, field := range fields {
		fieldResult := r.generateFieldValue(secret, field, generatedAt, logger)

		if fieldResult.skipRest {
			result.err = fieldResult.err
			result.skipRest = true
			return result
		}

		if fieldResult.value != nil {
			secret.Data[field] = fieldResult.value
			result.changed = true
			if fieldResult.rotated {
				result.rotated = true
			}
		}
	}

	return result
}

// updateSecretAndEmitEvents updates the secret in Kubernetes and emits appropriate events.
// It returns an error if the update fails.
func (r *SecretReconciler) updateSecretAndEmitEvents(
	ctx context.Context,
	secret *corev1.Secret,
	rotated bool,
	logger logr.Logger,
) error {
	// Update metadata annotations
	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}
	secret.Annotations[AnnotationGeneratedAt] = r.now().Format(time.RFC3339)

	// Update the secret
	if err := r.Update(ctx, secret); err != nil {
		logger.Error(err, "Failed to update Secret")
		return err
	}

	// Emit success event
	r.emitSuccessEvent(secret, rotated, logger)

	return nil
}

// emitSuccessEvent emits the appropriate success event based on whether rotation occurred.
func (r *SecretReconciler) emitSuccessEvent(secret *corev1.Secret, rotated bool, logger logr.Logger) {
	if rotated {
		if r.Config.Rotation.CreateEvents {
			r.EventRecorder.Event(secret, corev1.EventTypeNormal, EventReasonRotationSucceeded,
				"Successfully rotated values for secret fields")
		}
		logger.Info("Successfully rotated Secret values")
	} else {
		r.EventRecorder.Event(secret, corev1.EventTypeNormal, EventReasonGenerationSucceeded,
			"Successfully generated values for secret fields")
		logger.Info("Successfully updated Secret with generated values")
	}
}

// fieldGenerationResult contains the result of processing a single field
type fieldGenerationResult struct {
	field    string
	value    []byte
	rotated  bool
	err      error
	errMsg   string
	skipRest bool // if true, skip remaining fields and return error
}

// rotationCheckResult contains the result of checking if a field needs rotation
type rotationCheckResult struct {
	needsRotation     bool
	rotationInterval  time.Duration
	timeUntilRotation *time.Duration
	err               error
	errMsg            string
}

// parseSecretAnnotations parses the autogenerate annotation and returns the list of fields to generate.
// Returns nil if the annotation is not present or empty.
func parseSecretAnnotations(annotations map[string]string) []string {
	autogenerate, ok := annotations[AnnotationAutogenerate]
	if !ok || autogenerate == "" {
		return nil
	}
	return parseFields(autogenerate)
}

// checkFieldRotation checks if a field needs rotation based on annotations and timestamps.
// It returns the rotation check result including whether rotation is needed and the time until next rotation.
func (r *SecretReconciler) checkFieldRotation(annotations map[string]string, field string, generatedAt *time.Time) rotationCheckResult {
	rotationInterval := r.getFieldRotationInterval(annotations, field)

	result := rotationCheckResult{
		rotationInterval: rotationInterval,
	}

	if rotationInterval <= 0 {
		return result
	}

	// Validate rotation interval against minInterval
	if rotationInterval < r.Config.Rotation.MinInterval.Duration() {
		result.err = fmt.Errorf("rotation interval %s for field %q is below minimum %s",
			rotationInterval, field, r.Config.Rotation.MinInterval.Duration())
		result.errMsg = result.err.Error()
		return result
	}

	if generatedAt != nil {
		timeSinceGeneration := r.since(*generatedAt)
		if timeSinceGeneration >= rotationInterval {
			result.needsRotation = true
		} else {
			timeUntilRotation := rotationInterval - timeSinceGeneration
			result.timeUntilRotation = &timeUntilRotation
		}
	} else {
		// If rotation is configured but no generated-at timestamp exists,
		// we need to calculate the next rotation based on when we generate now
		result.timeUntilRotation = &rotationInterval
	}

	return result
}

// generateFieldValue generates a value for a single field based on its configuration.
// It handles existing values, rotation checks, and value generation.
func (r *SecretReconciler) generateFieldValue(
	secret *corev1.Secret,
	field string,
	generatedAt *time.Time,
	logger logr.Logger,
) fieldGenerationResult {
	result := fieldGenerationResult{field: field}

	// Check if field already has a value
	_, fieldExists := secret.Data[field]

	// Check rotation status
	rotationCheck := r.checkFieldRotation(secret.Annotations, field, generatedAt)

	// Handle rotation validation error
	// Note: We still allow initial generation even if rotation interval is invalid
	if rotationCheck.err != nil {
		logger.Error(nil, rotationCheck.errMsg, "field", field)
		r.EventRecorder.Event(secret, corev1.EventTypeWarning, EventReasonRotationFailed, rotationCheck.errMsg)
		// If field exists, skip it (invalid rotation config prevents rotation)
		// If field doesn't exist, we still generate the initial value
		if fieldExists {
			return result
		}
		// Continue to generate initial value, but rotation won't work
	}

	// Skip if field already has a value and doesn't need rotation
	if fieldExists && !rotationCheck.needsRotation {
		logger.V(1).Info("Field already has value, skipping", "field", field)
		return result
	}

	// Get field-specific generation parameters
	genType := r.getFieldType(secret.Annotations, field)
	length := r.getFieldLength(secret.Annotations, field)

	// Generate the value
	value, err := r.Generator.Generate(genType, length)
	if err != nil {
		result.err = fmt.Errorf("failed to generate value for field %s: %w", field, err)
		result.errMsg = fmt.Sprintf("Failed to generate value for field %q: %v", field, err)
		result.skipRest = true
		logger.Error(err, "Failed to generate value", "field", field, "type", genType)
		r.EventRecorder.Event(secret, corev1.EventTypeWarning, EventReasonGenerationFailed, result.errMsg)
		return result
	}

	result.value = []byte(value)
	result.rotated = rotationCheck.needsRotation

	if rotationCheck.needsRotation {
		logger.Info("Rotated value for field", "field", field, "type", genType, "length", length)
	} else {
		logger.Info("Generated value for field", "field", field, "type", genType, "length", length)
	}

	return result
}

// calculateNextRotation calculates the next rotation time based on all fields with rotation configured.
// It returns the minimum time until the next rotation across all fields.
func (r *SecretReconciler) calculateNextRotation(annotations map[string]string, fields []string, generatedAt *time.Time) *time.Duration {
	var nextRotation *time.Duration

	for _, field := range fields {
		rotationCheck := r.checkFieldRotation(annotations, field, generatedAt)

		// Skip fields with validation errors
		if rotationCheck.err != nil {
			continue
		}

		if rotationCheck.timeUntilRotation != nil {
			if nextRotation == nil || *rotationCheck.timeUntilRotation < *nextRotation {
				nextRotation = rotationCheck.timeUntilRotation
			}
		} else if rotationCheck.rotationInterval > 0 {
			// For fields that were just generated/rotated
			if nextRotation == nil || rotationCheck.rotationInterval < *nextRotation {
				nextRotation = &rotationCheck.rotationInterval
			}
		}
	}

	return nextRotation
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
