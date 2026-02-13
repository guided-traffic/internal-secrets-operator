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
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/guided-traffic/internal-secrets-operator/internal/controller"
	"github.com/guided-traffic/internal-secrets-operator/pkg/config"
	"github.com/guided-traffic/internal-secrets-operator/pkg/generator"
)

var (
	restConfig *rest.Config
	testEnv    *envtest.Environment

	// Counter for unique controller names
	controllerCounter int64
)

func TestMain(m *testing.M) {
	// Configure logger without stacktraces for cleaner test output
	// StacktraceLevel set to panic means stacktraces only appear for panic-level logs
	logf.SetLogger(zap.New(
		zap.WriteTo(os.Stdout),
		zap.UseDevMode(false),
		zap.StacktraceLevel(zapcore.PanicLevel),
	))

	// Set KUBEBUILDER_ASSETS if not already set (for local development on macOS ARM64)
	// In CI/CD, this will already be set by the Makefile to the correct platform
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		projectRoot := getProjectRoot()
		kubebuilderAssets := filepath.Join(projectRoot, "bin", "k8s", "1.29.0-darwin-arm64")
		os.Setenv("KUBEBUILDER_ASSETS", kubebuilderAssets)
	}

	testEnv = &envtest.Environment{
		ErrorIfCRDPathMissing: false,
	}

	var err error
	restConfig, err = testEnv.Start()
	if err != nil {
		logf.Log.Error(err, "failed to start test environment")
		os.Exit(1)
	}

	err = corev1.AddToScheme(scheme.Scheme)
	if err != nil {
		logf.Log.Error(err, "failed to add corev1 to scheme")
		os.Exit(1)
	}

	// Add rbacv1 to scheme (needed for RBAC tests)
	err = rbacv1.AddToScheme(scheme.Scheme)
	if err != nil {
		logf.Log.Error(err, "failed to add rbacv1 to scheme")
		os.Exit(1)
	}

	// Run tests
	code := m.Run()

	// Cleanup - use defer with panic recovery to ensure exit code is preserved
	func() {
		defer func() {
			if r := recover(); r != nil {
				logf.Log.Info("recovered from panic during cleanup", "panic", r)
			}
		}()
		if err := testEnv.Stop(); err != nil {
			logf.Log.Error(err, "failed to stop test environment (ignoring)")
		}
	}()

	os.Exit(code)
}

// testContext holds test dependencies
type testContext struct {
	client client.Client
	cancel context.CancelFunc
}

// MockClock is a mock implementation of Clock for testing
type MockClock struct {
	currentTime time.Time
}

// Now returns the mocked current time
func (m *MockClock) Now() time.Time {
	return m.currentTime
}

// SetTime sets the mocked current time
func (m *MockClock) SetTime(t time.Time) {
	m.currentTime = t
}

// Advance advances the mocked time by the given duration
func (m *MockClock) Advance(d time.Duration) {
	m.currentTime = m.currentTime.Add(d)
}

// setupTestManager creates a manager with unique controller name for test isolation
func setupTestManager(t *testing.T, operatorConfig *config.Config) *testContext {
	return setupTestManagerWithClock(t, operatorConfig, nil)
}

// setupTestManagerWithClock creates a manager with an optional mock clock
func setupTestManagerWithClock(t *testing.T, operatorConfig *config.Config, clock controller.Clock) *testContext {
	t.Helper()

	// Disable metrics server to avoid port conflicts
	metricsAddr := "0"

	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme: scheme.Scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
	})
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	// Get event recorder from manager (uses the new events API)
	eventRecorder := mgr.GetEventRecorder("secret-operator")

	if operatorConfig == nil {
		operatorConfig = config.NewDefaultConfig()
	}

	// Create generator with charset from config
	charset := operatorConfig.Defaults.String.BuildCharset()
	gen := generator.NewSecretGeneratorWithCharset(charset)

	reconciler := &controller.SecretReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		Generator:     gen,
		Config:        operatorConfig,
		EventRecorder: eventRecorder,
		Clock:         clock,
	}

	// Use unique controller name using atomic counter
	counter := atomic.AddInt64(&controllerCounter, 1)
	controllerName := "secret-controller-" + time.Now().Format("150405") + "-" + string(rune('a'+counter%26))

	err = ctrl.NewControllerManagedBy(mgr).
		Named(controllerName).
		For(&corev1.Secret{}).
		Complete(reconciler)
	if err != nil {
		t.Fatalf("failed to setup controller: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := mgr.Start(ctx); err != nil {
			t.Logf("manager stopped: %v", err)
		}
	}()

	// Wait for manager and cache to be ready
	time.Sleep(500 * time.Millisecond)

	return &testContext{
		client: mgr.GetClient(),
		cancel: cancel,
	}
}

// cleanup stops the manager and removes namespace
func (tc *testContext) cleanup(t *testing.T, ns *corev1.Namespace) {
	t.Helper()

	// Cancel context to stop manager
	tc.cancel()

	// Delete namespace
	if ns != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tc.client.Delete(ctx, ns)
	}
}

// createNamespace creates a unique namespace for test isolation
func createNamespace(t *testing.T, c client.Client) *corev1.Namespace {
	t.Helper()

	ns := &corev1.Namespace{
		ObjectMeta: ctrl.ObjectMeta{
			GenerateName: "test-",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := c.Create(ctx, ns); err != nil {
		t.Fatalf("failed to create namespace: %v", err)
	}

	return ns
}

// setupTestManagerWithReplicator creates a manager with SecretReplicatorReconciler
func setupTestManagerWithReplicator(t *testing.T, operatorConfig *config.Config) *testContext {
	t.Helper()

	// Disable metrics server to avoid port conflicts
	metricsAddr := "0"

	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme: scheme.Scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
	})
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	// Get event recorder from manager (uses the new events API)
	eventRecorder := mgr.GetEventRecorder("secret-replicator")

	if operatorConfig == nil {
		operatorConfig = config.NewDefaultConfig()
	}

	// Setup SecretReplicatorReconciler
	replicatorReconciler := &controller.SecretReplicatorReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		Config:        operatorConfig,
		EventRecorder: eventRecorder,
	}

	// Use unique controller name to avoid conflicts in tests
	counter := atomic.AddInt64(&controllerCounter, 1)
	controllerName := "secret-replicator-" + time.Now().Format("150405") + "-" + string(rune('a'+counter%26))

	// Use the proper SetupWithManagerAndName to ensure all watches are configured correctly
	err = replicatorReconciler.SetupWithManagerAndName(mgr, controllerName)
	if err != nil {
		t.Fatalf("failed to setup replicator controller: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := mgr.Start(ctx); err != nil {
			t.Logf("manager stopped: %v", err)
		}
	}()

	// Wait for manager and cache to be ready
	time.Sleep(500 * time.Millisecond)

	return &testContext{
		client: mgr.GetClient(),
		cancel: cancel,
	}
}

// getProjectRoot returns the project root directory
func getProjectRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "..", "..")
}
