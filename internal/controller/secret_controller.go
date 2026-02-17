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
	"k8s.io/client-go/tools/events"
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

	// AnnotationCurve specifies the default elliptic curve for ECDSA fields
	AnnotationCurve = AnnotationPrefix + "curve"

	// AnnotationCurvePrefix is the prefix for field-specific curve annotations (curve.<field>)
	AnnotationCurvePrefix = AnnotationPrefix + "curve."

	// AnnotationGeneratedAt indicates when the value was generated
	AnnotationGeneratedAt = AnnotationPrefix + "generated-at"

	// AnnotationRotate specifies the default rotation interval for all fields
	AnnotationRotate = AnnotationPrefix + "rotate"

	// AnnotationRotatePrefix is the prefix for field-specific rotation annotations (rotate.<field>)
	AnnotationRotatePrefix = AnnotationPrefix + "rotate."

	// AnnotationStringUppercase specifies whether to include uppercase letters
	AnnotationStringUppercase = AnnotationPrefix + "string.uppercase"

	// AnnotationStringLowercase specifies whether to include lowercase letters
	AnnotationStringLowercase = AnnotationPrefix + "string.lowercase"

	// AnnotationStringNumbers specifies whether to include numbers
	AnnotationStringNumbers = AnnotationPrefix + "string.numbers"

	// AnnotationStringSpecialChars specifies whether to include special characters
	AnnotationStringSpecialChars = AnnotationPrefix + "string.specialChars"

	// AnnotationStringAllowedSpecialChars specifies which special characters to use
	AnnotationStringAllowedSpecialChars = AnnotationPrefix + "string.allowedSpecialChars"

	// Event reasons
	EventReasonGenerationFailed    = "GenerationFailed"
	EventReasonGenerationSucceeded = "GenerationSucceeded"
	EventReasonRotationSucceeded   = "RotationSucceeded"
	EventReasonRotationFailed      = "RotationFailed"
	EventReasonRotationDeferred    = "RotationDeferred"
)

// SecretReconciler reconciles a Secret object
type SecretReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Generator     generator.Generator
	Config        *config.Config
	EventRecorder events.EventRecorder
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
		// An error occurred during field processing. The error has already been logged
		// and a Warning event has been created. We don't modify the secret and don't
		// return an error (which would cause unnecessary retries).
		return ctrl.Result{}, nil
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

// getFieldCurve returns the ECDSA curve for a specific field.
// Priority: curve.<field> annotation > curve annotation > default curve (P-256)
func (r *SecretReconciler) getFieldCurve(annotations map[string]string, field string) string {
	// Check for field-specific curve annotation
	fieldCurveKey := AnnotationCurvePrefix + field
	if value, ok := annotations[fieldCurveKey]; ok && value != "" {
		return value
	}
	// Fall back to default curve annotation
	if value, ok := annotations[AnnotationCurve]; ok && value != "" {
		return value
	}
	// Default curve
	return config.DefaultECDSACurve
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

// parseBoolAnnotation parses a boolean annotation value.
// Returns the parsed value and true if the annotation exists and is valid.
// Valid values are "true", "false", "1", "0" (case-insensitive).
func parseBoolAnnotation(annotations map[string]string, key string) (bool, bool) {
	value, ok := annotations[key]
	if !ok {
		return false, false
	}
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "true", "1":
		return true, true
	case "false", "0":
		return false, true
	default:
		return false, false
	}
}

// charsetOptions holds the resolved charset configuration
type charsetOptions struct {
	uppercase           bool
	lowercase           bool
	numbers             bool
	specialChars        bool
	allowedSpecialChars string
}

// resolveCharsetOptions resolves charset options from annotations and config defaults.
// Priority: annotations > config defaults
func (r *SecretReconciler) resolveCharsetOptions(annotations map[string]string) charsetOptions {
	opts := charsetOptions{
		uppercase:           r.Config.Defaults.String.Uppercase,
		lowercase:           r.Config.Defaults.String.Lowercase,
		numbers:             r.Config.Defaults.String.Numbers,
		specialChars:        r.Config.Defaults.String.SpecialChars,
		allowedSpecialChars: r.Config.Defaults.String.AllowedSpecialChars,
	}

	// Override with annotations if present
	if val, ok := parseBoolAnnotation(annotations, AnnotationStringUppercase); ok {
		opts.uppercase = val
	}
	if val, ok := parseBoolAnnotation(annotations, AnnotationStringLowercase); ok {
		opts.lowercase = val
	}
	if val, ok := parseBoolAnnotation(annotations, AnnotationStringNumbers); ok {
		opts.numbers = val
	}
	if val, ok := parseBoolAnnotation(annotations, AnnotationStringSpecialChars); ok {
		opts.specialChars = val
	}
	// Note: We check for the annotation's existence, not just non-empty value
	// This allows users to explicitly set it to empty if they want to override the config
	if val, ok := annotations[AnnotationStringAllowedSpecialChars]; ok {
		opts.allowedSpecialChars = val
	}

	return opts
}

// validateCharsetOptions validates charset options.
func validateCharsetOptions(opts charsetOptions) error {
	// Validate that at least one charset option is enabled
	if !opts.uppercase && !opts.lowercase && !opts.numbers && !opts.specialChars {
		return fmt.Errorf("at least one charset option must be enabled (uppercase, lowercase, numbers, or specialChars)")
	}

	// Validate that if specialChars is enabled, allowedSpecialChars is not empty
	if opts.specialChars && opts.allowedSpecialChars == "" {
		return fmt.Errorf("allowedSpecialChars must not be empty when specialChars is enabled")
	}

	return nil
}

// buildCharsetString builds a charset string from charset options.
func buildCharsetString(opts charsetOptions) string {
	var charset string
	if opts.lowercase {
		charset += "abcdefghijklmnopqrstuvwxyz"
	}
	if opts.uppercase {
		charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if opts.numbers {
		charset += "0123456789"
	}
	if opts.specialChars {
		charset += opts.allowedSpecialChars
	}
	return charset
}

// getCharsetFromAnnotations builds a charset based on annotations.
// Priority: annotations > config defaults
// Returns the charset and an error if the configuration is invalid.
func (r *SecretReconciler) getCharsetFromAnnotations(annotations map[string]string) (string, error) {
	opts := r.resolveCharsetOptions(annotations)

	if err := validateCharsetOptions(opts); err != nil {
		return "", err
	}

	return buildCharsetString(opts), nil
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
			// For keypair types, also store the public key
			if fieldResult.publicKey != nil {
				secret.Data[field+".pub"] = fieldResult.publicKey
			}
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
			r.EventRecorder.Eventf(secret, nil, corev1.EventTypeNormal, EventReasonRotationSucceeded, "Rotate",
				"Successfully rotated values for secret fields")
		}
		logger.Info("Successfully rotated Secret values")
	} else {
		r.EventRecorder.Eventf(secret, nil, corev1.EventTypeNormal, EventReasonGenerationSucceeded, "Generate",
			"Successfully generated values for secret fields")
		logger.Info("Successfully updated Secret with generated values")
	}
}

// fieldGenerationResult contains the result of processing a single field
type fieldGenerationResult struct {
	field      string
	value      []byte
	publicKey  []byte // For keypair types: the public key value
	rotated    bool
	err        error
	errMsg     string
	skipRest   bool // if true, skip remaining fields and return error
}

// rotationCheckResult contains the result of checking if a field needs rotation
type rotationCheckResult struct {
	needsRotation     bool
	rotationInterval  time.Duration
	timeUntilRotation *time.Duration
	deferred          bool       // true if rotation was deferred due to maintenance window
	deferredUntil     *time.Time // when the next maintenance window starts
	deferredWindow    string     // name of the window to defer to (for logging)
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
			// Rotation is due - check if we're in a maintenance window
			if r.Config.Rotation.MaintenanceWindows.Enabled {
				now := r.now()
				if !r.Config.Rotation.MaintenanceWindows.IsInAnyWindow(now) {
					// Not in maintenance window - defer rotation
					result.deferred = true
					nextWindowStart := r.Config.Rotation.MaintenanceWindows.NextWindowStart(now)
					if !nextWindowStart.IsZero() {
						result.deferredUntil = &nextWindowStart
						timeUntilWindow := nextWindowStart.Sub(now)
						result.timeUntilRotation = &timeUntilWindow
						// Find the window name for logging
						for i := range r.Config.Rotation.MaintenanceWindows.Windows {
							w := &r.Config.Rotation.MaintenanceWindows.Windows[i]
							if w.NextStart(now).Equal(nextWindowStart) {
								result.deferredWindow = w.Name
								break
							}
						}
					}
					return result
				}
			}
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
		r.EventRecorder.Eventf(secret, nil, corev1.EventTypeWarning, EventReasonRotationFailed, "Rotate", rotationCheck.errMsg)
		// If field exists, skip it (invalid rotation config prevents rotation)
		// If field doesn't exist, we still generate the initial value
		if fieldExists {
			return result
		}
		// Continue to generate initial value, but rotation won't work
	}

	// Handle deferred rotation (outside maintenance window)
	if rotationCheck.deferred && fieldExists {
		windowInfo := ""
		if rotationCheck.deferredWindow != "" {
			windowInfo = fmt.Sprintf(" (window: %s)", rotationCheck.deferredWindow)
		}
		if rotationCheck.deferredUntil != nil {
			msg := fmt.Sprintf("Rotation for field %q deferred until next maintenance window at %s%s",
				field, rotationCheck.deferredUntil.Format(time.RFC3339), windowInfo)
			logger.Info(msg, "field", field, "deferredUntil", rotationCheck.deferredUntil)
			r.EventRecorder.Eventf(secret, nil, corev1.EventTypeNormal, EventReasonRotationDeferred, "Rotate", msg)
		} else {
			msg := fmt.Sprintf("Rotation for field %q deferred - no maintenance window configured", field)
			logger.Info(msg, "field", field)
		}
		return result
	}

	// Skip if field already has a value and doesn't need rotation
	if fieldExists && !rotationCheck.needsRotation {
		logger.V(1).Info("Field already has value, skipping", "field", field)
		return result
	}

	// Get field-specific generation parameters
	genType := r.getFieldType(secret.Annotations, field)
	length := r.getFieldLength(secret.Annotations, field)

	// Generate the value based on type
	switch genType {
	case config.TypeRSA:
		privateKeyPEM, publicKeyPEM, keypairErr := r.Generator.GenerateRSAKeypair(length)
		if keypairErr != nil {
			result.err = fmt.Errorf("failed to generate RSA keypair for field %s: %w", field, keypairErr)
			result.errMsg = fmt.Sprintf("Failed to generate RSA keypair for field %q: %v", field, keypairErr)
			result.skipRest = true
			logger.Error(keypairErr, "Failed to generate RSA keypair", "field", field, "bits", length)
			r.EventRecorder.Eventf(secret, nil, corev1.EventTypeWarning, EventReasonGenerationFailed, "Generate", result.errMsg)
			return result
		}
		result.value = []byte(privateKeyPEM)
		result.publicKey = []byte(publicKeyPEM)

	case config.TypeECDSA:
		curveName := r.getFieldCurve(secret.Annotations, field)
		privateKeyPEM, publicKeyPEM, keypairErr := r.Generator.GenerateECDSAKeypair(curveName)
		if keypairErr != nil {
			result.err = fmt.Errorf("failed to generate ECDSA keypair for field %s: %w", field, keypairErr)
			result.errMsg = fmt.Sprintf("Failed to generate ECDSA keypair for field %q: %v", field, keypairErr)
			result.skipRest = true
			logger.Error(keypairErr, "Failed to generate ECDSA keypair", "field", field, "curve", curveName)
			r.EventRecorder.Eventf(secret, nil, corev1.EventTypeWarning, EventReasonGenerationFailed, "Generate", result.errMsg)
			return result
		}
		result.value = []byte(privateKeyPEM)
		result.publicKey = []byte(publicKeyPEM)

	case config.TypeEd25519:
		privateKeyPEM, publicKeyPEM, keypairErr := r.Generator.GenerateEd25519Keypair()
		if keypairErr != nil {
			result.err = fmt.Errorf("failed to generate Ed25519 keypair for field %s: %w", field, keypairErr)
			result.errMsg = fmt.Sprintf("Failed to generate Ed25519 keypair for field %q: %v", field, keypairErr)
			result.skipRest = true
			logger.Error(keypairErr, "Failed to generate Ed25519 keypair", "field", field)
			r.EventRecorder.Eventf(secret, nil, corev1.EventTypeWarning, EventReasonGenerationFailed, "Generate", result.errMsg)
			return result
		}
		result.value = []byte(privateKeyPEM)
		result.publicKey = []byte(publicKeyPEM)

	case "string", "":
		charset, charsetErr := r.getCharsetFromAnnotations(secret.Annotations)
		if charsetErr != nil {
			result.err = fmt.Errorf("invalid charset configuration for field %s: %w", field, charsetErr)
			result.errMsg = fmt.Sprintf("Invalid charset configuration for field %q: %v", field, charsetErr)
			result.skipRest = true
			logger.Error(charsetErr, "Invalid charset configuration", "field", field)
			r.EventRecorder.Eventf(secret, nil, corev1.EventTypeWarning, EventReasonGenerationFailed, "Generate", result.errMsg)
			return result
		}
		value, genErr := r.Generator.GenerateWithCharset(genType, length, charset)
		if genErr != nil {
			result.err = fmt.Errorf("failed to generate value for field %s: %w", field, genErr)
			result.errMsg = fmt.Sprintf("Failed to generate value for field %q: %v", field, genErr)
			result.skipRest = true
			logger.Error(genErr, "Failed to generate value", "field", field, "type", genType)
			r.EventRecorder.Eventf(secret, nil, corev1.EventTypeWarning, EventReasonGenerationFailed, "Generate", result.errMsg)
			return result
		}
		result.value = []byte(value)

	default:
		// For bytes and any other type, use default Generate method
		value, genErr := r.Generator.Generate(genType, length)
		if genErr != nil {
			result.err = fmt.Errorf("failed to generate value for field %s: %w", field, genErr)
			result.errMsg = fmt.Sprintf("Failed to generate value for field %q: %v", field, genErr)
			result.skipRest = true
			logger.Error(genErr, "Failed to generate value", "field", field, "type", genType)
			r.EventRecorder.Eventf(secret, nil, corev1.EventTypeWarning, EventReasonGenerationFailed, "Generate", result.errMsg)
			return result
		}
		result.value = []byte(value)
	}

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
		Named("secret-generator").
		For(&corev1.Secret{}).
		WithEventFilter(hasAutogenerateAnnotation).
		Complete(r)
}
