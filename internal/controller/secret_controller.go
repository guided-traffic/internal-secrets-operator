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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/guided-traffic/k8s-secret-generator/pkg/generator"
)

const (
	// AnnotationPrefix is the prefix for all secret generator annotations
	AnnotationPrefix = "secgen.gtrfc.com/"

	// AnnotationAutogenerate specifies which fields to auto-generate
	AnnotationAutogenerate = AnnotationPrefix + "autogenerate"

	// AnnotationType specifies the type of generated value (string, base64, uuid, hex)
	AnnotationType = AnnotationPrefix + "type"

	// AnnotationLength specifies the length of the generated value
	AnnotationLength = AnnotationPrefix + "length"

	// AnnotationSecure indicates the value was securely generated
	AnnotationSecure = AnnotationPrefix + "secure"

	// AnnotationGeneratedAt indicates when the value was generated
	AnnotationGeneratedAt = AnnotationPrefix + "generated-at"

	// AnnotationRegenerate forces regeneration of the secret
	AnnotationRegenerate = AnnotationPrefix + "regenerate"
)

// SecretReconciler reconciles a Secret object
type SecretReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Generator     generator.Generator
	DefaultLength int
	DefaultType   string
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

	// Get generation parameters
	genType := r.getAnnotationOrDefault(secret.Annotations, AnnotationType, r.DefaultType)
	length := r.getLengthAnnotation(secret.Annotations)

	// Check if regeneration is requested
	regenerate := secret.Annotations[AnnotationRegenerate] == "true"

	// Initialize data map if nil
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}

	// Track if any changes were made
	changed := false

	// Generate values for each field
	for _, field := range fields {
		// Skip if field already has a value and regeneration is not requested
		if _, exists := secret.Data[field]; exists && !regenerate {
			logger.V(1).Info("Field already has value, skipping", "field", field)
			continue
		}

		// Generate the value
		value, err := r.Generator.Generate(genType, length)
		if err != nil {
			logger.Error(err, "Failed to generate value", "field", field, "type", genType)
			return ctrl.Result{}, fmt.Errorf("failed to generate value for field %s: %w", field, err)
		}

		// Store the value as raw bytes - Kubernetes will handle base64 encoding
		// when storing in etcd and displaying via kubectl
		secret.Data[field] = []byte(value)
		changed = true
		logger.Info("Generated value for field", "field", field, "type", genType, "length", length)
	}

	// If changes were made, update the secret
	if changed {
		// Update metadata annotations
		if secret.Annotations == nil {
			secret.Annotations = make(map[string]string)
		}
		secret.Annotations[AnnotationType] = genType
		secret.Annotations[AnnotationSecure] = "yes"
		secret.Annotations[AnnotationGeneratedAt] = time.Now().Format(time.RFC3339)

		// Remove regenerate annotation if present
		delete(secret.Annotations, AnnotationRegenerate)

		// Update the secret
		if err := r.Update(ctx, &secret); err != nil {
			logger.Error(err, "Failed to update Secret")
			return ctrl.Result{}, err
		}

		logger.Info("Successfully updated Secret with generated values")
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

// getLengthAnnotation returns the length annotation value or the default
func (r *SecretReconciler) getLengthAnnotation(annotations map[string]string) int {
	if value, ok := annotations[AnnotationLength]; ok && value != "" {
		if length, err := strconv.Atoi(value); err == nil && length > 0 {
			return length
		}
	}
	return r.DefaultLength
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
