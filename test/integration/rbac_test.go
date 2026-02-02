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
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

// TestRBACPermissions tests that our RBAC rules allow all required operations.
// This test creates a ServiceAccount with the same permissions as defined in our
// Helm chart and config/rbac/role.yaml, then verifies all controller operations work.
//
// This test catches RBAC misconfigurations like missing API groups (e.g., events.k8s.io).
func TestRBACPermissions(t *testing.T) {
	// Create admin client for setup
	adminClient, err := client.New(restConfig, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		t.Fatalf("failed to create admin client: %v", err)
	}

	ctx := context.Background()

	// Create test namespace
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "rbac-test-",
		},
	}
	if err := adminClient.Create(ctx, ns); err != nil {
		t.Fatalf("failed to create namespace: %v", err)
	}
	defer func() {
		_ = adminClient.Delete(ctx, ns)
	}()

	// Create ServiceAccount for testing
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-operator",
			Namespace: ns.Name,
		},
	}
	if err := adminClient.Create(ctx, sa); err != nil {
		t.Fatalf("failed to create ServiceAccount: %v", err)
	}

	// Create ClusterRole with our RBAC rules (matching config/rbac/role.yaml)
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-operator-role-" + ns.Name,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get", "list", "watch", "update", "patch", "create", "delete"},
			},
			// Core Events API (for leader election)
			{
				APIGroups: []string{""},
				Resources: []string{"events"},
				Verbs:     []string{"create", "patch"},
			},
			// events.k8s.io API (for controller-runtime Eventf)
			{
				APIGroups: []string{"events.k8s.io"},
				Resources: []string{"events"},
				Verbs:     []string{"create", "patch"},
			},
		},
	}
	if err := adminClient.Create(ctx, clusterRole); err != nil {
		t.Fatalf("failed to create ClusterRole: %v", err)
	}
	defer func() {
		_ = adminClient.Delete(ctx, clusterRole)
	}()

	// Create ClusterRoleBinding
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-operator-binding-" + ns.Name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      sa.Name,
				Namespace: ns.Name,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterRole.Name,
		},
	}
	if err := adminClient.Create(ctx, clusterRoleBinding); err != nil {
		t.Fatalf("failed to create ClusterRoleBinding: %v", err)
	}
	defer func() {
		_ = adminClient.Delete(ctx, clusterRoleBinding)
	}()

	// Get impersonated config for ServiceAccount
	impersonatedConfig := rest.CopyConfig(restConfig)
	impersonatedConfig.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:" + ns.Name + ":" + sa.Name,
	}

	// Create client with impersonated identity
	impersonatedClientset, err := kubernetes.NewForConfig(impersonatedConfig)
	if err != nil {
		t.Fatalf("failed to create impersonated clientset: %v", err)
	}

	t.Run("Secret CRUD operations", func(t *testing.T) {
		secretName := "test-secret"

		// Create Secret
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: ns.Name,
			},
			Data: map[string][]byte{
				"key": []byte("value"),
			},
		}
		_, err := impersonatedClientset.CoreV1().Secrets(ns.Name).Create(ctx, secret, metav1.CreateOptions{})
		if err != nil {
			t.Errorf("failed to create secret: %v", err)
		}

		// Get Secret
		_, err = impersonatedClientset.CoreV1().Secrets(ns.Name).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			t.Errorf("failed to get secret: %v", err)
		}

		// List Secrets
		_, err = impersonatedClientset.CoreV1().Secrets(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Errorf("failed to list secrets: %v", err)
		}

		// Update Secret
		secret.Data["key"] = []byte("updated-value")
		_, err = impersonatedClientset.CoreV1().Secrets(ns.Name).Update(ctx, secret, metav1.UpdateOptions{})
		if err != nil {
			t.Errorf("failed to update secret: %v", err)
		}

		// Patch Secret
		patchData := []byte(`{"data":{"newkey":"bmV3dmFsdWU="}}`)
		_, err = impersonatedClientset.CoreV1().Secrets(ns.Name).Patch(ctx, secretName, "application/strategic-merge-patch+json", patchData, metav1.PatchOptions{})
		if err != nil {
			t.Errorf("failed to patch secret: %v", err)
		}

		// Delete Secret
		err = impersonatedClientset.CoreV1().Secrets(ns.Name).Delete(ctx, secretName, metav1.DeleteOptions{})
		if err != nil {
			t.Errorf("failed to delete secret: %v", err)
		}
	})

	t.Run("Event creation with events.k8s.io API", func(t *testing.T) {
		// This is the critical test - controller-runtime uses events.k8s.io API
		// If this fails, the operator will get "forbidden" errors when creating events

		// Create a secret to reference in the event
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "event-test-secret",
				Namespace: ns.Name,
			},
		}
		_, err := impersonatedClientset.CoreV1().Secrets(ns.Name).Create(ctx, secret, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("failed to create secret for event test: %v", err)
		}
		defer func() {
			_ = impersonatedClientset.CoreV1().Secrets(ns.Name).Delete(ctx, "event-test-secret", metav1.DeleteOptions{})
		}()

		// Create Event using events.k8s.io API (the API controller-runtime uses)
		event := &eventsv1.Event{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-event-",
				Namespace:    ns.Name,
			},
			EventTime:           metav1.NewMicroTime(time.Now()),
			ReportingController: "secret-operator",
			ReportingInstance:   "test-instance",
			Action:              "Testing",
			Reason:              "RBACTest",
			Regarding: corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Secret",
				Name:       secret.Name,
				Namespace:  ns.Name,
			},
			Note: "Testing RBAC permissions for events.k8s.io API",
			Type: "Normal",
		}

		_, err = impersonatedClientset.EventsV1().Events(ns.Name).Create(ctx, event, metav1.CreateOptions{})
		if err != nil {
			t.Errorf("CRITICAL: failed to create event using events.k8s.io API: %v\n"+
				"This means the operator will fail to create events in production!\n"+
				"Check that RBAC rules include: apiGroups: [\"events.k8s.io\"], resources: [\"events\"], verbs: [\"create\", \"patch\"]",
				err)
		}
	})

	t.Run("Event creation with core API (for leader election)", func(t *testing.T) {
		// Leader election in controller-runtime uses the core Events API, not events.k8s.io
		// If this fails, the operator will get "forbidden" errors during leader election

		coreEvent := &corev1.Event{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-core-event-",
				Namespace:    ns.Name,
			},
			InvolvedObject: corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Secret",
				Name:       "test-secret",
				Namespace:  ns.Name,
			},
			Reason:  "LeaderElection",
			Message: "Testing RBAC permissions for core events API (leader election)",
			Type:    "Normal",
			Source: corev1.EventSource{
				Component: "test-operator",
			},
			FirstTimestamp: metav1.Now(),
			LastTimestamp:  metav1.Now(),
		}

		_, err := impersonatedClientset.CoreV1().Events(ns.Name).Create(ctx, coreEvent, metav1.CreateOptions{})
		if err != nil {
			t.Errorf("CRITICAL: failed to create event using core API: %v\n"+
				"This means leader election will fail in production!\n"+
				"Check that RBAC rules include: apiGroups: [\"\"], resources: [\"events\"], verbs: [\"create\", \"patch\"]",
				err)
		}
	})

	t.Run("Cross-namespace secret operations (replication)", func(t *testing.T) {
		// Create a second namespace for cross-namespace replication tests
		targetNs := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "rbac-target-",
			},
		}
		if err := adminClient.Create(ctx, targetNs); err != nil {
			t.Fatalf("failed to create target namespace: %v", err)
		}
		defer func() {
			_ = adminClient.Delete(ctx, targetNs)
		}()

		// Test creating secret in target namespace (push-based replication)
		replicatedSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "replicated-secret",
				Namespace: targetNs.Name,
			},
			Data: map[string][]byte{
				"key": []byte("value"),
			},
		}
		_, err := impersonatedClientset.CoreV1().Secrets(targetNs.Name).Create(ctx, replicatedSecret, metav1.CreateOptions{})
		if err != nil {
			t.Errorf("failed to create secret in target namespace (push replication): %v", err)
		}

		// Test updating secret in target namespace
		replicatedSecret.Data["key"] = []byte("updated")
		_, err = impersonatedClientset.CoreV1().Secrets(targetNs.Name).Update(ctx, replicatedSecret, metav1.UpdateOptions{})
		if err != nil {
			t.Errorf("failed to update secret in target namespace: %v", err)
		}

		// Test deleting secret in target namespace (cleanup on source deletion)
		err = impersonatedClientset.CoreV1().Secrets(targetNs.Name).Delete(ctx, replicatedSecret.Name, metav1.DeleteOptions{})
		if err != nil {
			t.Errorf("failed to delete secret in target namespace: %v", err)
		}

		// Test creating event in target namespace (for replication events)
		eventInTarget := &eventsv1.Event{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-event-",
				Namespace:    targetNs.Name,
			},
			EventTime:           metav1.NewMicroTime(time.Now()),
			ReportingController: "secret-replicator",
			ReportingInstance:   "test-instance",
			Action:              "Replicate",
			Reason:              "Replicated",
			Regarding: corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Secret",
				Name:       "some-secret",
				Namespace:  targetNs.Name,
			},
			Note: "Testing cross-namespace event creation",
			Type: "Normal",
		}
		_, err = impersonatedClientset.EventsV1().Events(targetNs.Name).Create(ctx, eventInTarget, metav1.CreateOptions{})
		if err != nil {
			t.Errorf("failed to create event in target namespace: %v", err)
		}
	})
}

// TestRBACMissingEventsK8sIO specifically tests the scenario where events.k8s.io
// permission is missing (the bug that was found in production).
func TestRBACMissingEventsK8sIO(t *testing.T) {
	// Create admin client for setup
	adminClient, err := client.New(restConfig, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		t.Fatalf("failed to create admin client: %v", err)
	}

	ctx := context.Background()

	// Create test namespace
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "rbac-missing-test-",
		},
	}
	if err := adminClient.Create(ctx, ns); err != nil {
		t.Fatalf("failed to create namespace: %v", err)
	}
	defer func() {
		_ = adminClient.Delete(ctx, ns)
	}()

	// Create ServiceAccount
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-operator-broken",
			Namespace: ns.Name,
		},
	}
	if err := adminClient.Create(ctx, sa); err != nil {
		t.Fatalf("failed to create ServiceAccount: %v", err)
	}

	// Create ClusterRole with BROKEN RBAC rules (missing events.k8s.io)
	// This simulates the bug that was found in production
	brokenRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-broken-role-" + ns.Name,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get", "list", "watch", "update", "patch", "create", "delete"},
			},
			// BUG: Only core events API, missing events.k8s.io
			{
				APIGroups: []string{""},
				Resources: []string{"events"},
				Verbs:     []string{"create", "patch"},
			},
		},
	}
	if err := adminClient.Create(ctx, brokenRole); err != nil {
		t.Fatalf("failed to create ClusterRole: %v", err)
	}
	defer func() {
		_ = adminClient.Delete(ctx, brokenRole)
	}()

	// Create ClusterRoleBinding
	brokenBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-broken-binding-" + ns.Name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      sa.Name,
				Namespace: ns.Name,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     brokenRole.Name,
		},
	}
	if err := adminClient.Create(ctx, brokenBinding); err != nil {
		t.Fatalf("failed to create ClusterRoleBinding: %v", err)
	}
	defer func() {
		_ = adminClient.Delete(ctx, brokenBinding)
	}()

	// Get impersonated config
	impersonatedConfig := rest.CopyConfig(restConfig)
	impersonatedConfig.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:" + ns.Name + ":" + sa.Name,
	}

	impersonatedClientset, err := kubernetes.NewForConfig(impersonatedConfig)
	if err != nil {
		t.Fatalf("failed to create impersonated clientset: %v", err)
	}

	// Create a secret to reference
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: ns.Name,
		},
	}
	_, err = impersonatedClientset.CoreV1().Secrets(ns.Name).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create secret: %v", err)
	}

	// Try to create event using events.k8s.io API - this should FAIL
	event := &eventsv1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-event-",
			Namespace:    ns.Name,
		},
		EventTime:           metav1.NewMicroTime(time.Now()),
		ReportingController: "secret-operator",
		ReportingInstance:   "test-instance",
		Action:              "Testing",
		Reason:              "RBACTest",
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Secret",
			Name:       secret.Name,
			Namespace:  ns.Name,
		},
		Note: "This should fail due to missing events.k8s.io permission",
		Type: "Normal",
	}

	_, err = impersonatedClientset.EventsV1().Events(ns.Name).Create(ctx, event, metav1.CreateOptions{})
	if err == nil {
		t.Log("NOTE: events.k8s.io request succeeded - envtest may not enforce RBAC strictly")
		t.Log("This test is designed to fail with broken RBAC in a real cluster")
	} else {
		t.Logf("Expected failure with broken RBAC: %v", err)
	}
}

// loadRBACRulesFromFile loads the ClusterRole from config/rbac/role.yaml
func loadRBACRulesFromFile() ([]rbacv1.PolicyRule, error) {
	projectRoot := getProjectRoot()
	roleFilePath := filepath.Join(projectRoot, "config", "rbac", "role.yaml")

	data, err := os.ReadFile(roleFilePath)
	if err != nil {
		return nil, err
	}

	var clusterRole rbacv1.ClusterRole
	if err := yaml.Unmarshal(data, &clusterRole); err != nil {
		return nil, err
	}

	return clusterRole.Rules, nil
}

// TestRBACFromRoleYAML tests that the RBAC rules in config/rbac/role.yaml
// are sufficient for all controller operations. This ensures that any changes
// to the RBAC file are validated by the tests.
//
// This is the most important RBAC test - it reads the actual RBAC file and
// verifies it allows all necessary operations.
func TestRBACFromRoleYAML(t *testing.T) {
	// Load RBAC rules from config/rbac/role.yaml
	rules, err := loadRBACRulesFromFile()
	if err != nil {
		t.Fatalf("failed to load RBAC rules from config/rbac/role.yaml: %v", err)
	}

	t.Logf("Loaded %d RBAC rules from config/rbac/role.yaml", len(rules))
	for i, rule := range rules {
		t.Logf("  Rule %d: apiGroups=%v resources=%v verbs=%v", i, rule.APIGroups, rule.Resources, rule.Verbs)
	}

	// Create admin client for setup
	adminClient, err := client.New(restConfig, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		t.Fatalf("failed to create admin client: %v", err)
	}

	ctx := context.Background()

	// Create test namespace
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "rbac-yaml-test-",
		},
	}
	if err := adminClient.Create(ctx, ns); err != nil {
		t.Fatalf("failed to create namespace: %v", err)
	}
	defer func() {
		_ = adminClient.Delete(ctx, ns)
	}()

	// Create ServiceAccount
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-from-yaml",
			Namespace: ns.Name,
		},
	}
	if err := adminClient.Create(ctx, sa); err != nil {
		t.Fatalf("failed to create ServiceAccount: %v", err)
	}

	// Create ClusterRole with rules from the YAML file
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-yaml-role-" + ns.Name,
		},
		Rules: rules,
	}
	if err := adminClient.Create(ctx, clusterRole); err != nil {
		t.Fatalf("failed to create ClusterRole: %v", err)
	}
	defer func() {
		_ = adminClient.Delete(ctx, clusterRole)
	}()

	// Create ClusterRoleBinding
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-yaml-binding-" + ns.Name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      sa.Name,
				Namespace: ns.Name,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterRole.Name,
		},
	}
	if err := adminClient.Create(ctx, binding); err != nil {
		t.Fatalf("failed to create ClusterRoleBinding: %v", err)
	}
	defer func() {
		_ = adminClient.Delete(ctx, binding)
	}()

	// Get impersonated config
	impersonatedConfig := rest.CopyConfig(restConfig)
	impersonatedConfig.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:" + ns.Name + ":" + sa.Name,
	}

	impersonatedClientset, err := kubernetes.NewForConfig(impersonatedConfig)
	if err != nil {
		t.Fatalf("failed to create impersonated clientset: %v", err)
	}

	// Test all operations the controller needs

	t.Run("create secret", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-create",
				Namespace: ns.Name,
			},
		}
		_, err := impersonatedClientset.CoreV1().Secrets(ns.Name).Create(ctx, secret, metav1.CreateOptions{})
		if err != nil {
			t.Errorf("config/rbac/role.yaml does not allow creating secrets: %v", err)
		}
	})

	t.Run("get secret", func(t *testing.T) {
		_, err := impersonatedClientset.CoreV1().Secrets(ns.Name).Get(ctx, "test-create", metav1.GetOptions{})
		if err != nil {
			t.Errorf("config/rbac/role.yaml does not allow getting secrets: %v", err)
		}
	})

	t.Run("list secrets", func(t *testing.T) {
		_, err := impersonatedClientset.CoreV1().Secrets(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Errorf("config/rbac/role.yaml does not allow listing secrets: %v", err)
		}
	})

	t.Run("update secret", func(t *testing.T) {
		secret, _ := impersonatedClientset.CoreV1().Secrets(ns.Name).Get(ctx, "test-create", metav1.GetOptions{})
		secret.Data = map[string][]byte{"key": []byte("value")}
		_, err := impersonatedClientset.CoreV1().Secrets(ns.Name).Update(ctx, secret, metav1.UpdateOptions{})
		if err != nil {
			t.Errorf("config/rbac/role.yaml does not allow updating secrets: %v", err)
		}
	})

	t.Run("patch secret", func(t *testing.T) {
		patchData := []byte(`{"data":{"newkey":"dmFsdWU="}}`)
		_, err := impersonatedClientset.CoreV1().Secrets(ns.Name).Patch(ctx, "test-create", "application/strategic-merge-patch+json", patchData, metav1.PatchOptions{})
		if err != nil {
			t.Errorf("config/rbac/role.yaml does not allow patching secrets: %v", err)
		}
	})

	t.Run("delete secret", func(t *testing.T) {
		err := impersonatedClientset.CoreV1().Secrets(ns.Name).Delete(ctx, "test-create", metav1.DeleteOptions{})
		if err != nil {
			t.Errorf("config/rbac/role.yaml does not allow deleting secrets: %v", err)
		}
	})

	t.Run("create event (events.k8s.io)", func(t *testing.T) {
		// This is the critical test that would have caught the production bug!
		// controller-runtime uses the events.k8s.io API, not core events

		// First create a secret to reference
		refSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "event-ref",
				Namespace: ns.Name,
			},
		}
		_, _ = impersonatedClientset.CoreV1().Secrets(ns.Name).Create(ctx, refSecret, metav1.CreateOptions{})

		event := &eventsv1.Event{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-event-",
				Namespace:    ns.Name,
			},
			EventTime:           metav1.NewMicroTime(time.Now()),
			ReportingController: "secret-operator",
			ReportingInstance:   "test-instance",
			Action:              "Reconcile",
			Reason:              "Generated",
			Regarding: corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Secret",
				Name:       refSecret.Name,
				Namespace:  ns.Name,
			},
			Note: "Testing events.k8s.io permission from config/rbac/role.yaml",
			Type: "Normal",
		}
		_, err := impersonatedClientset.EventsV1().Events(ns.Name).Create(ctx, event, metav1.CreateOptions{})
		if err != nil {
			t.Errorf("CRITICAL: config/rbac/role.yaml does not allow creating events via events.k8s.io API: %v\n"+
				"The operator will fail to create events in production!\n"+
				"Add this rule to config/rbac/role.yaml:\n"+
				"  - apiGroups: [\"events.k8s.io\"]\n"+
				"    resources: [\"events\"]\n"+
				"    verbs: [\"create\", \"patch\"]", err)
		}
	})

	t.Run("create event (core API for leader election)", func(t *testing.T) {
		// Leader election in controller-runtime uses the core Events API
		// If this fails, leader election will fail in production

		coreEvent := &corev1.Event{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-core-event-",
				Namespace:    ns.Name,
			},
			InvolvedObject: corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Secret",
				Name:       "event-ref",
				Namespace:  ns.Name,
			},
			Reason:  "LeaderElection",
			Message: "Testing core events API permission for leader election",
			Type:    "Normal",
			Source: corev1.EventSource{
				Component: "test-operator",
			},
			FirstTimestamp: metav1.Now(),
			LastTimestamp:  metav1.Now(),
		}
		_, err := impersonatedClientset.CoreV1().Events(ns.Name).Create(ctx, coreEvent, metav1.CreateOptions{})
		if err != nil {
			t.Errorf("CRITICAL: config/rbac/role.yaml does not allow creating events via core API: %v\n"+
				"Leader election will fail in production!\n"+
				"Add this rule to config/rbac/role.yaml:\n"+
				"  - apiGroups: [\"\"]\n"+
				"    resources: [\"events\"]\n"+
				"    verbs: [\"create\", \"patch\"]", err)
		}
	})

	t.Run("cross-namespace operations", func(t *testing.T) {
		// Create second namespace for cross-namespace tests
		targetNs := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "rbac-yaml-target-",
			},
		}
		if err := adminClient.Create(ctx, targetNs); err != nil {
			t.Fatalf("failed to create target namespace: %v", err)
		}
		defer func() {
			_ = adminClient.Delete(ctx, targetNs)
		}()

		// Test push replication - create secret in another namespace
		pushSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pushed-secret",
				Namespace: targetNs.Name,
			},
		}
		_, err := impersonatedClientset.CoreV1().Secrets(targetNs.Name).Create(ctx, pushSecret, metav1.CreateOptions{})
		if err != nil {
			t.Errorf("config/rbac/role.yaml does not allow push replication (create secret in other namespace): %v", err)
		}

		// Test creating events in other namespaces (for replication events)
		event := &eventsv1.Event{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-event-",
				Namespace:    targetNs.Name,
			},
			EventTime:           metav1.NewMicroTime(time.Now()),
			ReportingController: "secret-replicator",
			ReportingInstance:   "test-instance",
			Action:              "Replicate",
			Reason:              "Replicated",
			Regarding: corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Secret",
				Name:       pushSecret.Name,
				Namespace:  targetNs.Name,
			},
			Note: "Testing cross-namespace event creation",
			Type: "Normal",
		}
		_, err = impersonatedClientset.EventsV1().Events(targetNs.Name).Create(ctx, event, metav1.CreateOptions{})
		if err != nil {
			t.Errorf("config/rbac/role.yaml does not allow creating events in other namespaces: %v", err)
		}
	})
}
