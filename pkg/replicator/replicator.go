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

package replicator

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// AnnotationPrefix is the prefix for all replication annotations
	AnnotationPrefix = "iso.gtrfc.com/"

	// AnnotationReplicatableFromNamespaces allowlist of namespaces that can replicate FROM this Secret
	AnnotationReplicatableFromNamespaces = AnnotationPrefix + "replicatable-from-namespaces"

	// AnnotationReplicateFrom source Secret to replicate data from (format: "namespace/secret-name")
	AnnotationReplicateFrom = AnnotationPrefix + "replicate-from"

	// AnnotationReplicateTo push this secret to specified namespaces (comma-separated)
	AnnotationReplicateTo = AnnotationPrefix + "replicate-to"

	// AnnotationReplicatedFrom indicates this Secret was replicated from another Secret
	AnnotationReplicatedFrom = AnnotationPrefix + "replicated-from"

	// AnnotationLastReplicatedAt timestamp of last replication
	AnnotationLastReplicatedAt = AnnotationPrefix + "last-replicated-at"

	// FinalizerReplicateToCleanup finalizer for cleaning up pushed Secrets
	FinalizerReplicateToCleanup = AnnotationPrefix + "replicate-to-cleanup"
)

// ReplicateSecret copies data from source Secret to target Secret
func ReplicateSecret(source, target *corev1.Secret) {
	// Initialize target data if nil
	if target.Data == nil {
		target.Data = make(map[string][]byte)
	}

	// Copy all data from source to target (overwrite existing)
	for key, value := range source.Data {
		target.Data[key] = value
	}

	// Add replication status annotations
	if target.Annotations == nil {
		target.Annotations = make(map[string]string)
	}
	target.Annotations[AnnotationReplicatedFrom] = fmt.Sprintf("%s/%s", source.Namespace, source.Name)
	target.Annotations[AnnotationLastReplicatedAt] = time.Now().Format(time.RFC3339)
}

// ValidateReplication checks if replication is allowed (mutual consent)
func ValidateReplication(sourceNamespace string, sourceAllowlist string, targetNamespace string) (bool, error) {
	if sourceAllowlist == "" {
		return false, fmt.Errorf("source Secret does not have %s annotation", AnnotationReplicatableFromNamespaces)
	}

	// Split comma-separated list
	allowedNamespaces := strings.Split(sourceAllowlist, ",")

	for _, pattern := range allowedNamespaces {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}

		// Check if pattern matches target namespace
		matched, err := MatchNamespace(targetNamespace, pattern)
		if err != nil {
			return false, fmt.Errorf("invalid pattern %q: %w", pattern, err)
		}
		if matched {
			return true, nil
		}
	}

	return false, fmt.Errorf("target namespace %q is not in source allowlist %q", targetNamespace, sourceAllowlist)
}

// MatchNamespace checks if a namespace matches a glob pattern
// Supports glob patterns: *, ?, [abc], [a-z], [0-9]
func MatchNamespace(namespace, pattern string) (bool, error) {
	// Use filepath.Match for glob pattern matching
	// filepath.Match supports: *, ?, [abc], [a-z]
	matched, err := filepath.Match(pattern, namespace)
	if err != nil {
		return false, fmt.Errorf("invalid glob pattern: %w", err)
	}
	return matched, nil
}

// ParseSourceReference parses "namespace/secret-name" format
func ParseSourceReference(sourceRef string) (namespace, name string, err error) {
	parts := strings.SplitN(sourceRef, "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid source reference format: expected 'namespace/secret-name', got %q", sourceRef)
	}

	namespace = strings.TrimSpace(parts[0])
	name = strings.TrimSpace(parts[1])

	if namespace == "" || name == "" {
		return "", "", fmt.Errorf("invalid source reference: namespace and name cannot be empty")
	}

	return namespace, name, nil
}

// ParseTargetNamespaces parses comma-separated list of target namespaces
func ParseTargetNamespaces(targetNS string) []string {
	if targetNS == "" {
		return nil
	}

	parts := strings.Split(targetNS, ",")
	result := make([]string, 0, len(parts))

	for _, ns := range parts {
		ns = strings.TrimSpace(ns)
		if ns != "" {
			result = append(result, ns)
		}
	}

	return result
}

// HasFinalizer checks if a Secret has the replication finalizer
func HasFinalizer(secret *corev1.Secret) bool {
	for _, f := range secret.Finalizers {
		if f == FinalizerReplicateToCleanup {
			return true
		}
	}
	return false
}

// AddFinalizer adds the replication finalizer to a Secret
func AddFinalizer(secret *corev1.Secret) {
	if HasFinalizer(secret) {
		return
	}
	secret.Finalizers = append(secret.Finalizers, FinalizerReplicateToCleanup)
}

// RemoveFinalizer removes the replication finalizer from a Secret
func RemoveFinalizer(secret *corev1.Secret) {
	finalizers := make([]string, 0, len(secret.Finalizers))
	for _, f := range secret.Finalizers {
		if f != FinalizerReplicateToCleanup {
			finalizers = append(finalizers, f)
		}
	}
	secret.Finalizers = finalizers
}

// IsOwnedByUs checks if a Secret was replicated by us (has our annotation)
func IsOwnedByUs(secret *corev1.Secret, expectedSource string) bool {
	if secret.Annotations == nil {
		return false
	}
	actual := secret.Annotations[AnnotationReplicatedFrom]
	return actual == expectedSource
}

// IsBeingDeleted checks if a Secret is being deleted (has DeletionTimestamp)
func IsBeingDeleted(secret *corev1.Secret) bool {
	return !secret.DeletionTimestamp.IsZero()
}

// GetReplicatedFromAnnotation returns the value of the replicated-from annotation
func GetReplicatedFromAnnotation(secret *corev1.Secret) string {
	if secret.Annotations == nil {
		return ""
	}
	return secret.Annotations[AnnotationReplicatedFrom]
}

// HasConflictingAnnotations checks if autogenerate and replicate-from are both present
func HasConflictingAnnotations(secret *corev1.Secret) bool {
	if secret.Annotations == nil {
		return false
	}
	hasAutogenerate := secret.Annotations[AnnotationPrefix+"autogenerate"] != ""
	hasReplicateFrom := secret.Annotations[AnnotationReplicateFrom] != ""
	return hasAutogenerate && hasReplicateFrom
}

// CreateReplicatedSecret creates a new Secret for replication
func CreateReplicatedSecret(source *corev1.Secret, targetNamespace string) *corev1.Secret {
	target := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      source.Name,
			Namespace: targetNamespace,
			Labels:    make(map[string]string),
			Annotations: map[string]string{
				AnnotationReplicatedFrom:   fmt.Sprintf("%s/%s", source.Namespace, source.Name),
				AnnotationLastReplicatedAt: time.Now().Format(time.RFC3339),
			},
		},
		Type: source.Type,
		Data: make(map[string][]byte),
	}

	// Copy labels from source (optional, can be customized)
	for key, value := range source.Labels {
		target.Labels[key] = value
	}

	// Copy data
	for key, value := range source.Data {
		target.Data[key] = value
	}

	return target
}
