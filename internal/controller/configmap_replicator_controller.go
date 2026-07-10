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
	"k8s.io/client-go/tools/events"
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

// ConfigMapReplicatorReconciler reconciles ConfigMaps for replication
// (both pull and push), mirroring the Secret replicator behavior.
type ConfigMapReplicatorReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Config        *config.Config
	EventRecorder events.EventRecorder
}

// Reconcile handles ConfigMap replication (both pull and push)
func (r *ConfigMapReplicatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Fetch the ConfigMap
	cm := &corev1.ConfigMap{}
	if err := r.Get(ctx, req.NamespacedName, cm); err != nil {
		if apierrors.IsNotFound(err) {
			// ConfigMap deleted - handled by finalizer
			return ctrl.Result{}, nil
		}
		log.Error(err, "failed to get ConfigMap")
		return ctrl.Result{}, err
	}

	// Handle deletion (for push-based replication cleanup)
	if replicator.IsBeingDeleted(cm) {
		return r.handleDeletion(ctx, cm)
	}

	// Handle pull-based replication
	if cm.Annotations[replicator.AnnotationReplicateFrom] != "" {
		return r.handlePullReplication(ctx, cm)
	}

	// Handle push-based replication
	if cm.Annotations[replicator.AnnotationReplicateTo] != "" {
		return r.handlePushReplication(ctx, cm)
	}

	return ctrl.Result{}, nil
}

// handlePullReplication implements pull-based replication (target pulls from source)
func (r *ConfigMapReplicatorReconciler) handlePullReplication(ctx context.Context, targetCM *corev1.ConfigMap) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Parse source reference
	sourceRef := targetCM.Annotations[replicator.AnnotationReplicateFrom]
	sourceNamespace, sourceName, err := replicator.ParseSourceReference(sourceRef)
	if err != nil {
		r.EventRecorder.Eventf(targetCM, nil, corev1.EventTypeWarning, EventReasonReplicationFailed, "Pull",
			fmt.Sprintf("Invalid source reference: %v", err))
		log.Error(err, "invalid source reference", "sourceRef", sourceRef)
		return ctrl.Result{}, nil // Don't requeue - user needs to fix annotation
	}

	// Fetch source ConfigMap
	sourceCM := &corev1.ConfigMap{}
	sourceKey := types.NamespacedName{Namespace: sourceNamespace, Name: sourceName}
	if err := r.Get(ctx, sourceKey, sourceCM); err != nil {
		if apierrors.IsNotFound(err) {
			r.EventRecorder.Eventf(targetCM, nil, corev1.EventTypeWarning, EventReasonReplicationFailed, "Pull",
				fmt.Sprintf("Source ConfigMap %s not found", sourceRef))
			log.Info("Source ConfigMap not found", "source", sourceRef)
			return ctrl.Result{}, nil
		}
		log.Error(err, "failed to get source ConfigMap", "source", sourceRef)
		return ctrl.Result{}, err
	}

	// Check if source ConfigMap was deleted
	if replicator.IsBeingDeleted(sourceCM) {
		r.EventRecorder.Eventf(targetCM, nil, corev1.EventTypeWarning, EventReasonSourceDeleted, "Pull",
			fmt.Sprintf("Source ConfigMap %s is being deleted. Target will keep last known data.", sourceRef))
		log.Info("Source ConfigMap being deleted - keeping snapshot", "source", sourceRef)
		return ctrl.Result{}, nil
	}

	// Validate replication is allowed (mutual consent or global pull-based permission)
	sourceAllowlist := sourceCM.Annotations[replicator.AnnotationReplicatableFromNamespaces]
	allowed, denyReason := replicator.ValidatePullConsent(r.Config.GlobalPullBasedPermissions, replicator.KindConfigMap,
		sourceNamespace, sourceName, sourceAllowlist, targetCM.Namespace)
	if !allowed {
		r.EventRecorder.Eventf(targetCM, nil, corev1.EventTypeWarning, EventReasonReplicationFailed, "Pull",
			fmt.Sprintf("Replication not allowed: %s", denyReason))
		log.Info("Replication not allowed", "source", sourceRef, "reason", denyReason)
		return ctrl.Result{}, nil // Don't requeue - consent required
	}

	// Replicate data from source to target
	replicator.ReplicateConfigMap(sourceCM, targetCM)

	// Update target ConfigMap
	if err := r.Update(ctx, targetCM); err != nil {
		r.EventRecorder.Eventf(targetCM, nil, corev1.EventTypeWarning, EventReasonReplicationFailed, "Pull",
			fmt.Sprintf("Failed to update target ConfigMap: %v", err))
		log.Error(err, "failed to update target ConfigMap")
		return ctrl.Result{}, err
	}

	r.EventRecorder.Eventf(targetCM, nil, corev1.EventTypeNormal, EventReasonReplicationSucceeded, "Pull",
		fmt.Sprintf("Successfully replicated from %s", sourceRef))
	log.Info("Pull replication succeeded", "target", fmt.Sprintf("%s/%s", targetCM.Namespace, targetCM.Name), "source", sourceRef)

	return ctrl.Result{}, nil
}

// handlePushReplication implements push-based replication (source pushes to targets)
func (r *ConfigMapReplicatorReconciler) handlePushReplication(ctx context.Context, sourceCM *corev1.ConfigMap) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Parse target namespaces
	targetNSList := sourceCM.Annotations[replicator.AnnotationReplicateTo]
	targetNamespaces := replicator.ParseTargetNamespaces(targetNSList)

	if len(targetNamespaces) == 0 {
		log.Info("No target namespaces specified", "annotation", targetNSList)
		return ctrl.Result{}, nil
	}

	// Add finalizer to source ConfigMap for cleanup
	if !replicator.HasFinalizer(sourceCM) {
		replicator.AddFinalizer(sourceCM)
		if err := r.Update(ctx, sourceCM); err != nil {
			log.Error(err, "failed to add finalizer to source ConfigMap")
			return ctrl.Result{}, err
		}
		log.Info("Added finalizer to source ConfigMap", "namespace", sourceCM.Namespace, "name", sourceCM.Name)
	}

	sourceRef := fmt.Sprintf("%s/%s", sourceCM.Namespace, sourceCM.Name)

	// Push to each target namespace
	for _, targetNS := range targetNamespaces {
		r.pushToNamespace(ctx, sourceCM, targetNS, sourceRef)
		// Always continue with other namespaces even if one fails
	}

	return ctrl.Result{}, nil
}

// pushToNamespace pushes a ConfigMap to a target namespace
func (r *ConfigMapReplicatorReconciler) pushToNamespace(ctx context.Context, sourceCM *corev1.ConfigMap, targetNS string, sourceRef string) {
	log := log.FromContext(ctx)

	// Check if target ConfigMap already exists
	targetCM := &corev1.ConfigMap{}
	targetKey := types.NamespacedName{Namespace: targetNS, Name: sourceCM.Name}
	err := r.Get(ctx, targetKey, targetCM)

	if err != nil {
		if apierrors.IsNotFound(err) {
			// Target doesn't exist - create it
			targetCM = replicator.CreateReplicatedConfigMap(sourceCM, targetNS)
			if err := r.Create(ctx, targetCM); err != nil {
				reasonMsg := humanReadableErrorReason(err)
				r.EventRecorder.Eventf(sourceCM, nil, corev1.EventTypeWarning, EventReasonPushFailed, "Push",
					fmt.Sprintf("Could not replicate to namespace %s: %s", targetNS, reasonMsg))
				log.V(1).Info("Could not replicate to namespace", "targetNamespace", targetNS, "reason", reasonMsg)
				return
			}
			log.Info("Created replicated ConfigMap", "targetNamespace", targetNS, "name", targetCM.Name)
			return
		}

		// Unexpected error reading target
		reasonMsg := humanReadableErrorReason(err)
		r.EventRecorder.Eventf(sourceCM, nil, corev1.EventTypeWarning, EventReasonPushFailed, "Push",
			fmt.Sprintf("Could not access namespace %s: %s", targetNS, reasonMsg))
		log.V(1).Info("Could not access namespace", "targetNamespace", targetNS, "reason", reasonMsg)
		return
	}

	// Target exists - check if we own it
	if !replicator.IsOwnedByUs(targetCM, sourceRef) {
		r.EventRecorder.Eventf(sourceCM, nil, corev1.EventTypeWarning, EventReasonPushFailed, "Push",
			fmt.Sprintf("ConfigMap already exists in namespace %s and is not managed by this replication", targetNS))
		log.V(1).Info("Target ConfigMap exists but is not owned by us", "targetNamespace", targetNS, "name", sourceCM.Name)
		return
	}

	// We own it - update it
	replicator.ReplicateConfigMap(sourceCM, targetCM)
	if err := r.Update(ctx, targetCM); err != nil {
		reasonMsg := humanReadableErrorReason(err)
		r.EventRecorder.Eventf(sourceCM, nil, corev1.EventTypeWarning, EventReasonPushFailed, "Push",
			fmt.Sprintf("Could not update ConfigMap in namespace %s: %s", targetNS, reasonMsg))
		log.V(1).Info("Could not update ConfigMap in namespace", "targetNamespace", targetNS, "reason", reasonMsg)
		return
	}

	log.Info("Updated replicated ConfigMap", "targetNamespace", targetNS, "name", targetCM.Name)
}

// handleDeletion handles cleanup when a source ConfigMap with replicate-to is deleted
func (r *ConfigMapReplicatorReconciler) handleDeletion(ctx context.Context, sourceCM *corev1.ConfigMap) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	if !replicator.HasFinalizer(sourceCM) {
		// No finalizer - nothing to clean up
		return ctrl.Result{}, nil
	}

	// Only handle deletion for ConfigMaps with replicate-to annotation
	if sourceCM.Annotations[replicator.AnnotationReplicateTo] == "" {
		// Remove finalizer and let it be deleted
		replicator.RemoveFinalizer(sourceCM)
		if err := r.Update(ctx, sourceCM); err != nil {
			log.Error(err, "failed to remove finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	sourceRef := fmt.Sprintf("%s/%s", sourceCM.Namespace, sourceCM.Name)

	// Find all ConfigMaps that were replicated from this source
	cmList := &corev1.ConfigMapList{}
	if err := r.List(ctx, cmList); err != nil {
		log.Error(err, "failed to list ConfigMaps for cleanup")
		return ctrl.Result{}, err
	}

	// Delete all pushed ConfigMaps
	for i := range cmList.Items {
		cm := &cmList.Items[i]
		if replicator.GetReplicatedFromAnnotation(cm) == sourceRef {
			if err := r.Delete(ctx, cm); err != nil && !apierrors.IsNotFound(err) {
				log.Error(err, "failed to delete replicated ConfigMap", "namespace", cm.Namespace, "name", cm.Name)
				return ctrl.Result{}, err
			}
			log.Info("Deleted replicated ConfigMap", "namespace", cm.Namespace, "name", cm.Name)
		}
	}

	// Remove finalizer from source ConfigMap
	replicator.RemoveFinalizer(sourceCM)
	if err := r.Update(ctx, sourceCM); err != nil {
		log.Error(err, "failed to remove finalizer after cleanup")
		return ctrl.Result{}, err
	}

	log.Info("Cleaned up all replicated ConfigMaps", "source", sourceRef)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *ConfigMapReplicatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndName(mgr, "configmap-replicator")
}

// SetupWithManagerAndName sets up the controller with the Manager using a custom name.
// This is useful for testing where multiple controllers may run in the same process.
func (r *ConfigMapReplicatorReconciler) SetupWithManagerAndName(mgr ctrl.Manager, name string) error {
	// Predicate for main reconciliation: only handle ConfigMaps with pull or push annotations
	mainPredicate := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		cm, ok := obj.(*corev1.ConfigMap)
		if !ok {
			return false
		}
		if cm.Annotations == nil {
			return false
		}
		hasReplicateFrom := cm.Annotations[replicator.AnnotationReplicateFrom] != ""
		hasReplicateTo := cm.Annotations[replicator.AnnotationReplicateTo] != ""
		return hasReplicateFrom || hasReplicateTo
	})

	// Predicate for source ConfigMaps: trigger target reconciliation when source changes
	sourcePredicate := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		cm, ok := obj.(*corev1.ConfigMap)
		if !ok {
			return false
		}
		// ConfigMaps with replicatable-from-namespaces can be sources
		if cm.Annotations != nil &&
			cm.Annotations[replicator.AnnotationReplicatableFromNamespaces] != "" {
			return true
		}
		// ConfigMaps covered by a global pull-based permission can be sources too
		return replicator.MatchesAnyGlobalSource(r.Config.GlobalPullBasedPermissions, replicator.KindConfigMap,
			cm.Namespace, cm.Name)
	})

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		// Watch ConfigMaps with replicate-from or replicate-to annotations
		For(&corev1.ConfigMap{}, builder.WithPredicates(mainPredicate)).
		// Watch source ConfigMaps to trigger reconciliation of target ConfigMaps when the source changes
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.findTargetsForSource),
			builder.WithPredicates(sourcePredicate),
		).
		// Watch all ConfigMaps to detect when a conflicting target is deleted
		// This enables push-based replication to retry when the blocking ConfigMap is removed
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.findPushSourcesForTarget),
		).
		Complete(r)
}

// findPushSourcesForTarget finds all source ConfigMaps that want to push to a namespace
// where a ConfigMap was deleted. This enables retry when a conflicting ConfigMap is removed.
func (r *ConfigMapReplicatorReconciler) findPushSourcesForTarget(ctx context.Context, obj client.Object) []reconcile.Request {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return nil
	}

	log := log.FromContext(ctx)

	// Find all ConfigMaps with replicate-to annotation that includes this namespace
	cmList := &corev1.ConfigMapList{}
	if err := r.List(ctx, cmList); err != nil {
		log.Error(err, "failed to list ConfigMaps for push source mapping")
		return nil
	}

	var requests []reconcile.Request
	for i := range cmList.Items {
		source := &cmList.Items[i]
		if source.Annotations == nil {
			continue
		}

		// Check if this source pushes to the namespace where the ConfigMap changed
		replicateTo := source.Annotations[replicator.AnnotationReplicateTo]
		if replicateTo == "" {
			continue
		}

		// Check if the deleted/changed ConfigMap has the same name and is in a target namespace
		if source.Name != cm.Name {
			continue
		}

		targetNamespaces := replicator.ParseTargetNamespaces(replicateTo)
		for _, targetNS := range targetNamespaces {
			if targetNS == cm.Namespace {
				// This source wants to push to the namespace where the ConfigMap changed
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Namespace: source.Namespace,
						Name:      source.Name,
					},
				})
				log.V(1).Info("Found push source for target change", "source", fmt.Sprintf("%s/%s", source.Namespace, source.Name), "targetNamespace", cm.Namespace)
				break
			}
		}
	}

	if len(requests) > 0 {
		log.Info("Triggering reconciliation of push sources", "changedConfigMap", fmt.Sprintf("%s/%s", cm.Namespace, cm.Name), "sourceCount", len(requests))
	}

	return requests
}

// findTargetsForSource finds all target ConfigMaps that replicate from a given source ConfigMap.
// This enables automatic sync when source ConfigMaps change.
func (r *ConfigMapReplicatorReconciler) findTargetsForSource(ctx context.Context, obj client.Object) []reconcile.Request {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return nil
	}

	log := log.FromContext(ctx)
	sourceRef := fmt.Sprintf("%s/%s", cm.Namespace, cm.Name)

	// Find all ConfigMaps with replicate-from annotation pointing to this source
	cmList := &corev1.ConfigMapList{}
	if err := r.List(ctx, cmList); err != nil {
		log.Error(err, "failed to list ConfigMaps for reverse mapping", "source", sourceRef)
		return nil
	}

	var requests []reconcile.Request
	for i := range cmList.Items {
		target := &cmList.Items[i]
		if target.Annotations == nil {
			continue
		}

		// Check if this target pulls from our source
		if target.Annotations[replicator.AnnotationReplicateFrom] == sourceRef {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: target.Namespace,
					Name:      target.Name,
				},
			})
			log.V(1).Info("Found target ConfigMap for source", "source", sourceRef, "target", fmt.Sprintf("%s/%s", target.Namespace, target.Name))
		}
	}

	if len(requests) > 0 {
		log.Info("Triggering reconciliation of target ConfigMaps", "source", sourceRef, "targetCount", len(requests))
	}

	return requests
}
