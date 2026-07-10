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

// ConfigMapReplicatorReconciler reconciles ConfigMaps for pull-based replication.
// Unlike the Secret replicator, it supports only pull-based replication:
// a target ConfigMap with the replicate-from annotation pulls data from a
// source ConfigMap, if allowed by the source-side allowlist annotation or a
// global pull-based permission.
type ConfigMapReplicatorReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Config        *config.Config
	EventRecorder events.EventRecorder
}

// Reconcile handles ConfigMap pull-based replication
func (r *ConfigMapReplicatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Fetch the ConfigMap
	cm := &corev1.ConfigMap{}
	if err := r.Get(ctx, req.NamespacedName, cm); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		log.Error(err, "failed to get ConfigMap")
		return ctrl.Result{}, err
	}

	// Pull-based replication does not own the target, nothing to clean up on deletion
	if replicator.IsConfigMapBeingDeleted(cm) {
		return ctrl.Result{}, nil
	}

	// Handle pull-based replication
	if cm.Annotations[replicator.AnnotationReplicateFrom] != "" {
		return r.handlePullReplication(ctx, cm)
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
	if replicator.IsConfigMapBeingDeleted(sourceCM) {
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

// SetupWithManager sets up the controller with the Manager
func (r *ConfigMapReplicatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndName(mgr, "configmap-replicator")
}

// SetupWithManagerAndName sets up the controller with the Manager using a custom name.
// This is useful for testing where multiple controllers may run in the same process.
func (r *ConfigMapReplicatorReconciler) SetupWithManagerAndName(mgr ctrl.Manager, name string) error {
	// Predicate for main reconciliation: only handle ConfigMaps with the pull annotation
	mainPredicate := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		cm, ok := obj.(*corev1.ConfigMap)
		if !ok {
			return false
		}
		return cm.Annotations != nil && cm.Annotations[replicator.AnnotationReplicateFrom] != ""
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
		// Watch ConfigMaps with the replicate-from annotation
		For(&corev1.ConfigMap{}, builder.WithPredicates(mainPredicate)).
		// Watch source ConfigMaps to trigger reconciliation of target ConfigMaps when the source changes
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.findTargetsForSource),
			builder.WithPredicates(sourcePredicate),
		).
		Complete(r)
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
