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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/guided-traffic/internal-secrets-operator/pkg/config"
	"github.com/guided-traffic/internal-secrets-operator/pkg/replicator"
)

const (
	// Event reasons for replication
	EventReasonReplicationSucceeded = "ReplicationSucceeded"
	EventReasonReplicationFailed    = "ReplicationFailed"
	EventReasonPushFailed           = "PushFailed"
	EventReasonSourceDeleted        = "SourceDeleted"
	EventReasonConflictingFeatures  = "ConflictingFeatures"
)

// SecretReplicatorReconciler reconciles Secrets for replication
type SecretReplicatorReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Config        *config.Config
	EventRecorder record.EventRecorder
}

// Reconcile handles Secret replication (both pull and push)
func (r *SecretReplicatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Fetch the Secret
	secret := &corev1.Secret{}
	if err := r.Get(ctx, req.NamespacedName, secret); err != nil {
		if apierrors.IsNotFound(err) {
			// Secret deleted - handled by finalizer
			return ctrl.Result{}, nil
		}
		log.Error(err, "failed to get Secret")
		return ctrl.Result{}, err
	}

	// Handle deletion (for push-based replication cleanup)
	if replicator.IsBeingDeleted(secret) {
		return r.handleDeletion(ctx, secret)
	}

	// Check for conflicting annotations (autogenerate + replicate-from)
	if replicator.HasConflictingAnnotations(secret) {
		r.EventRecorder.Event(secret, corev1.EventTypeWarning, EventReasonConflictingFeatures,
			"Secret has both 'autogenerate' and 'replicate-from' annotations. These features cannot be used together.")
		log.Info("Skipping Secret with conflicting annotations", "namespace", secret.Namespace, "name", secret.Name)
		return ctrl.Result{}, nil
	}

	// Handle pull-based replication
	if secret.Annotations[replicator.AnnotationReplicateFrom] != "" {
		return r.handlePullReplication(ctx, secret)
	}

	// Handle push-based replication
	if secret.Annotations[replicator.AnnotationReplicateTo] != "" {
		return r.handlePushReplication(ctx, secret)
	}

	return ctrl.Result{}, nil
}

// handlePullReplication implements pull-based replication (target pulls from source)
func (r *SecretReplicatorReconciler) handlePullReplication(ctx context.Context, targetSecret *corev1.Secret) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Parse source reference
	sourceRef := targetSecret.Annotations[replicator.AnnotationReplicateFrom]
	sourceNamespace, sourceName, err := replicator.ParseSourceReference(sourceRef)
	if err != nil {
		r.EventRecorder.Event(targetSecret, corev1.EventTypeWarning, EventReasonReplicationFailed,
			fmt.Sprintf("Invalid source reference: %v", err))
		log.Error(err, "invalid source reference", "sourceRef", sourceRef)
		return ctrl.Result{}, nil // Don't requeue - user needs to fix annotation
	}

	// Fetch source Secret
	sourceSecret := &corev1.Secret{}
	sourceKey := types.NamespacedName{Namespace: sourceNamespace, Name: sourceName}
	if err := r.Get(ctx, sourceKey, sourceSecret); err != nil {
		if apierrors.IsNotFound(err) {
			r.EventRecorder.Event(targetSecret, corev1.EventTypeWarning, EventReasonReplicationFailed,
				fmt.Sprintf("Source Secret %s not found", sourceRef))
			log.Info("Source Secret not found", "source", sourceRef)
			return ctrl.Result{}, nil
		}
		log.Error(err, "failed to get source Secret", "source", sourceRef)
		return ctrl.Result{}, err
	}

	// Check if source Secret was deleted
	if replicator.IsBeingDeleted(sourceSecret) {
		r.EventRecorder.Event(targetSecret, corev1.EventTypeWarning, EventReasonSourceDeleted,
			fmt.Sprintf("Source Secret %s is being deleted. Target will keep last known data.", sourceRef))
		log.Info("Source Secret being deleted - keeping snapshot", "source", sourceRef)
		return ctrl.Result{}, nil
	}

	// Validate replication is allowed (mutual consent)
	sourceAllowlist := sourceSecret.Annotations[replicator.AnnotationReplicatableFromNamespaces]
	allowed, err := replicator.ValidateReplication(sourceNamespace, sourceAllowlist, targetSecret.Namespace)
	if err != nil || !allowed {
		r.EventRecorder.Event(targetSecret, corev1.EventTypeWarning, EventReasonReplicationFailed,
			fmt.Sprintf("Replication not allowed: %v", err))
		log.Info("Replication not allowed", "source", sourceRef, "error", err)
		return ctrl.Result{}, nil // Don't requeue - mutual consent required
	}

	// Replicate data from source to target
	replicator.ReplicateSecret(sourceSecret, targetSecret)

	// Update target Secret
	if err := r.Update(ctx, targetSecret); err != nil {
		r.EventRecorder.Event(targetSecret, corev1.EventTypeWarning, EventReasonReplicationFailed,
			fmt.Sprintf("Failed to update target Secret: %v", err))
		log.Error(err, "failed to update target Secret")
		return ctrl.Result{}, err
	}

	r.EventRecorder.Event(targetSecret, corev1.EventTypeNormal, EventReasonReplicationSucceeded,
		fmt.Sprintf("Successfully replicated from %s", sourceRef))
	log.Info("Pull replication succeeded", "target", fmt.Sprintf("%s/%s", targetSecret.Namespace, targetSecret.Name), "source", sourceRef)

	return ctrl.Result{}, nil
}

// handlePushReplication implements push-based replication (source pushes to targets)
func (r *SecretReplicatorReconciler) handlePushReplication(ctx context.Context, sourceSecret *corev1.Secret) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Parse target namespaces
	targetNSList := sourceSecret.Annotations[replicator.AnnotationReplicateTo]
	targetNamespaces := replicator.ParseTargetNamespaces(targetNSList)

	if len(targetNamespaces) == 0 {
		log.Info("No target namespaces specified", "annotation", targetNSList)
		return ctrl.Result{}, nil
	}

	// Add finalizer to source Secret for cleanup
	if !replicator.HasFinalizer(sourceSecret) {
		replicator.AddFinalizer(sourceSecret)
		if err := r.Update(ctx, sourceSecret); err != nil {
			log.Error(err, "failed to add finalizer to source Secret")
			return ctrl.Result{}, err
		}
		log.Info("Added finalizer to source Secret", "namespace", sourceSecret.Namespace, "name", sourceSecret.Name)
	}

	sourceRef := fmt.Sprintf("%s/%s", sourceSecret.Namespace, sourceSecret.Name)

	// Push to each target namespace
	for _, targetNS := range targetNamespaces {
		r.pushToNamespace(ctx, sourceSecret, targetNS, sourceRef)
		// Always continue with other namespaces even if one fails
	}

	return ctrl.Result{}, nil
}

// pushToNamespace pushes a Secret to a target namespace
func (r *SecretReplicatorReconciler) pushToNamespace(ctx context.Context, sourceSecret *corev1.Secret, targetNS string, sourceRef string) {
	log := log.FromContext(ctx)

	// Check if target Secret already exists
	targetSecret := &corev1.Secret{}
	targetKey := types.NamespacedName{Namespace: targetNS, Name: sourceSecret.Name}
	err := r.Get(ctx, targetKey, targetSecret)

	if err != nil {
		if apierrors.IsNotFound(err) {
			// Target doesn't exist - create it
			targetSecret = replicator.CreateReplicatedSecret(sourceSecret, targetNS)
			if err := r.Create(ctx, targetSecret); err != nil {
				// Determine if this is an expected error (namespace not found, permission denied, etc.)
				reasonMsg := r.getHumanReadableErrorReason(err)
				r.EventRecorder.Event(sourceSecret, corev1.EventTypeWarning, EventReasonPushFailed,
					fmt.Sprintf("Could not replicate to namespace %s: %s", targetNS, reasonMsg))
				log.V(1).Info("Could not replicate to namespace", "targetNamespace", targetNS, "reason", reasonMsg)
				return
			}
			log.Info("Created replicated Secret", "targetNamespace", targetNS, "name", targetSecret.Name)
			return
		}

		// Unexpected error reading target
		reasonMsg := r.getHumanReadableErrorReason(err)
		r.EventRecorder.Event(sourceSecret, corev1.EventTypeWarning, EventReasonPushFailed,
			fmt.Sprintf("Could not access namespace %s: %s", targetNS, reasonMsg))
		log.V(1).Info("Could not access namespace", "targetNamespace", targetNS, "reason", reasonMsg)
		return
	}

	// Target exists - check if we own it
	if !replicator.IsOwnedByUs(targetSecret, sourceRef) {
		r.EventRecorder.Event(sourceSecret, corev1.EventTypeWarning, EventReasonPushFailed,
			fmt.Sprintf("Secret already exists in namespace %s and is not managed by this replication", targetNS))
		log.V(1).Info("Target Secret exists but is not owned by us", "targetNamespace", targetNS, "name", sourceSecret.Name)
		return
	}

	// We own it - update it
	replicator.ReplicateSecret(sourceSecret, targetSecret)
	if err := r.Update(ctx, targetSecret); err != nil {
		reasonMsg := r.getHumanReadableErrorReason(err)
		r.EventRecorder.Event(sourceSecret, corev1.EventTypeWarning, EventReasonPushFailed,
			fmt.Sprintf("Could not update Secret in namespace %s: %s", targetNS, reasonMsg))
		log.V(1).Info("Could not update Secret in namespace", "targetNamespace", targetNS, "reason", reasonMsg)
		return
	}

	log.Info("Updated replicated Secret", "targetNamespace", targetNS, "name", targetSecret.Name)
}

// getHumanReadableErrorReason converts API errors to human-readable reasons
func (r *SecretReplicatorReconciler) getHumanReadableErrorReason(err error) string {
	if apierrors.IsNotFound(err) {
		return "namespace not found"
	}
	if apierrors.IsForbidden(err) {
		return "permission denied"
	}
	if apierrors.IsUnauthorized(err) {
		return "authentication failed"
	}
	if apierrors.IsInvalid(err) {
		return "invalid resource"
	}
	if apierrors.IsServiceUnavailable(err) {
		return "service temporarily unavailable"
	}
	// Return first 100 chars of error message for unexpected errors
	errMsg := err.Error()
	if len(errMsg) > 100 {
		return errMsg[:100] + "..."
	}
	return errMsg
}

// handleDeletion handles cleanup when a source Secret with replicate-to is deleted
func (r *SecretReplicatorReconciler) handleDeletion(ctx context.Context, sourceSecret *corev1.Secret) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	if !replicator.HasFinalizer(sourceSecret) {
		// No finalizer - nothing to clean up
		return ctrl.Result{}, nil
	}

	// Only handle deletion for secrets with replicate-to annotation
	if sourceSecret.Annotations[replicator.AnnotationReplicateTo] == "" {
		// Remove finalizer and let it be deleted
		replicator.RemoveFinalizer(sourceSecret)
		if err := r.Update(ctx, sourceSecret); err != nil {
			log.Error(err, "failed to remove finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	sourceRef := fmt.Sprintf("%s/%s", sourceSecret.Namespace, sourceSecret.Name)

	// Find all Secrets that were replicated from this source
	secretList := &corev1.SecretList{}
	if err := r.List(ctx, secretList); err != nil {
		log.Error(err, "failed to list Secrets for cleanup")
		return ctrl.Result{}, err
	}

	// Delete all pushed Secrets
	for i := range secretList.Items {
		secret := &secretList.Items[i]
		if replicator.GetReplicatedFromAnnotation(secret) == sourceRef {
			if err := r.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
				log.Error(err, "failed to delete replicated Secret", "namespace", secret.Namespace, "name", secret.Name)
				return ctrl.Result{}, err
			}
			log.Info("Deleted replicated Secret", "namespace", secret.Namespace, "name", secret.Name)
		}
	}

	// Remove finalizer from source Secret
	replicator.RemoveFinalizer(sourceSecret)
	if err := r.Update(ctx, sourceSecret); err != nil {
		log.Error(err, "failed to remove finalizer after cleanup")
		return ctrl.Result{}, err
	}

	log.Info("Cleaned up all replicated Secrets", "source", sourceRef)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *SecretReplicatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndName(mgr, "secret-replicator")
}

// SetupWithManagerAndName sets up the controller with the Manager using a custom name
// This is useful for testing where multiple controllers may run in the same process
func (r *SecretReplicatorReconciler) SetupWithManagerAndName(mgr ctrl.Manager, name string) error {
	// Predicate for main reconciliation: only handle Secrets with pull or push annotations
	mainPredicate := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		secret, ok := obj.(*corev1.Secret)
		if !ok {
			return false
		}

		if secret.Annotations == nil {
			return false
		}

		// Watch Secrets with replication annotations
		hasReplicateFrom := secret.Annotations[replicator.AnnotationReplicateFrom] != ""
		hasReplicateTo := secret.Annotations[replicator.AnnotationReplicateTo] != ""

		return hasReplicateFrom || hasReplicateTo
	})

	// Predicate for source Secrets: trigger target reconciliation when source changes
	sourcePredicate := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		secret, ok := obj.(*corev1.Secret)
		if !ok {
			return false
		}
		// Only watch Secrets that could be sources (have replicatable-from-namespaces)
		return secret.Annotations != nil &&
			secret.Annotations[replicator.AnnotationReplicatableFromNamespaces] != ""
	})

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		// Watch Secrets with replicate-from or replicate-to annotations
		For(&corev1.Secret{}, builder.WithPredicates(mainPredicate)).
		// Watch source Secrets to trigger reconciliation of target Secrets when source changes
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findTargetsForSource),
			builder.WithPredicates(sourcePredicate),
		).
		Complete(r)
}

// findTargetsForSource finds all target Secrets that replicate from a given source Secret
// This enables automatic sync when source Secrets change
func (r *SecretReplicatorReconciler) findTargetsForSource(ctx context.Context, obj client.Object) []reconcile.Request {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return nil
	}

	log := log.FromContext(ctx)
	sourceRef := fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)

	// Find all Secrets with replicate-from annotation pointing to this source
	secretList := &corev1.SecretList{}
	if err := r.List(ctx, secretList); err != nil {
		log.Error(err, "failed to list Secrets for reverse mapping", "source", sourceRef)
		return nil
	}

	var requests []reconcile.Request
	for i := range secretList.Items {
		target := &secretList.Items[i]
		if target.Annotations == nil {
			continue
		}

		// Check if this target pulls from our source
		targetSourceRef := target.Annotations[replicator.AnnotationReplicateFrom]
		if targetSourceRef == sourceRef {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: target.Namespace,
					Name:      target.Name,
				},
			})
			log.V(1).Info("Found target Secret for source", "source", sourceRef, "target", fmt.Sprintf("%s/%s", target.Namespace, target.Name))
		}
	}

	if len(requests) > 0 {
		log.Info("Triggering reconciliation of target Secrets", "source", sourceRef, "targetCount", len(requests))
	}

	return requests
}
