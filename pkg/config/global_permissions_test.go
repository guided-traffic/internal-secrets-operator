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

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestGlobalPullBasedPermissionValidate(t *testing.T) {
	tests := []struct {
		name        string
		perm        GlobalPullBasedPermission
		wantErr     bool
		errContains string
	}{
		{
			name: "valid secret permission",
			perm: GlobalPullBasedPermission{
				FromNamespace:     "namespace-a",
				ToNamespace:       "namespace-b",
				ValidationPattern: "shoot-*",
				AllowSecret:       true,
			},
		},
		{
			name: "valid configmap permission",
			perm: GlobalPullBasedPermission{
				FromNamespace:     "namespace-a",
				ToNamespace:       "namespace-b",
				ValidationPattern: "shoot-*",
				AllowConfigMap:    true,
			},
		},
		{
			name: "valid with both kinds allowed",
			perm: GlobalPullBasedPermission{
				FromNamespace:     "namespace-a",
				ToNamespace:       "namespace-b",
				ValidationPattern: "*",
				AllowSecret:       true,
				AllowConfigMap:    true,
			},
		},
		{
			name: "valid with multiple namespaces and whitespace",
			perm: GlobalPullBasedPermission{
				FromNamespace:     "ns-a, ns-b , ns-c",
				ToNamespace:       "ns-d,ns-e",
				ValidationPattern: "*",
				AllowSecret:       true,
			},
		},
		{
			name: "missing fromNamespace",
			perm: GlobalPullBasedPermission{
				ToNamespace:       "namespace-b",
				ValidationPattern: "*",
				AllowSecret:       true,
			},
			wantErr:     true,
			errContains: "fromNamespace",
		},
		{
			name: "fromNamespace with only commas and spaces",
			perm: GlobalPullBasedPermission{
				FromNamespace:     " , , ",
				ToNamespace:       "namespace-b",
				ValidationPattern: "*",
				AllowSecret:       true,
			},
			wantErr:     true,
			errContains: "fromNamespace",
		},
		{
			name: "missing toNamespace",
			perm: GlobalPullBasedPermission{
				FromNamespace:     "namespace-a",
				ValidationPattern: "*",
				AllowSecret:       true,
			},
			wantErr:     true,
			errContains: "toNamespace",
		},
		{
			name: "glob pattern in fromNamespace rejected",
			perm: GlobalPullBasedPermission{
				FromNamespace:     "shoot-*",
				ToNamespace:       "namespace-b",
				ValidationPattern: "*",
				AllowSecret:       true,
			},
			wantErr:     true,
			errContains: "exact",
		},
		{
			name: "wildcard toNamespace rejected",
			perm: GlobalPullBasedPermission{
				FromNamespace:     "namespace-a",
				ToNamespace:       "*",
				ValidationPattern: "*",
				AllowSecret:       true,
			},
			wantErr:     true,
			errContains: "exact",
		},
		{
			name: "uppercase namespace rejected",
			perm: GlobalPullBasedPermission{
				FromNamespace:     "NamespaceA",
				ToNamespace:       "namespace-b",
				ValidationPattern: "*",
				AllowSecret:       true,
			},
			wantErr:     true,
			errContains: "invalid namespace name",
		},
		{
			name: "empty validationPattern",
			perm: GlobalPullBasedPermission{
				FromNamespace: "namespace-a",
				ToNamespace:   "namespace-b",
				AllowSecret:   true,
			},
			wantErr:     true,
			errContains: "validationPattern",
		},
		{
			name: "invalid glob pattern",
			perm: GlobalPullBasedPermission{
				FromNamespace:     "namespace-a",
				ToNamespace:       "namespace-b",
				ValidationPattern: "[a-",
				AllowSecret:       true,
			},
			wantErr:     true,
			errContains: "invalid glob pattern",
		},
		{
			name: "neither secret nor configmap allowed",
			perm: GlobalPullBasedPermission{
				FromNamespace:     "namespace-a",
				ToNamespace:       "namespace-b",
				ValidationPattern: "*",
			},
			wantErr:     true,
			errContains: "at least one of allowSecret or allowConfigMap",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.perm.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("Validate() error = %q, expected to contain %q", err.Error(), tt.errContains)
			}
		})
	}
}

func TestGlobalPullBasedPermissionNamespaceLists(t *testing.T) {
	perm := GlobalPullBasedPermission{
		FromNamespace: " ns-a,ns-b , ,ns-c",
		ToNamespace:   "ns-d",
	}

	wantFrom := []string{"ns-a", "ns-b", "ns-c"}
	if got := perm.FromNamespaces(); !reflect.DeepEqual(got, wantFrom) {
		t.Errorf("FromNamespaces() = %v, want %v", got, wantFrom)
	}

	wantTo := []string{"ns-d"}
	if got := perm.ToNamespaces(); !reflect.DeepEqual(got, wantTo) {
		t.Errorf("ToNamespaces() = %v, want %v", got, wantTo)
	}
}

func TestLoadConfigWithGlobalPullBasedPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
defaults:
  type: string
  length: 32
globalPullBasedPermissions:
  - fromNamespace: "namespace-a"
    toNamespace: "namespace-b,namespace-c"
    validationPattern: "shoot-*"
    allowConfigMap: true
    allowSecret: false
  - fromNamespace: "garden"
    toNamespace: "staging"
    validationPattern: "*"
    allowSecret: true
`
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if len(cfg.GlobalPullBasedPermissions) != 2 {
		t.Fatalf("expected 2 permissions, got %d", len(cfg.GlobalPullBasedPermissions))
	}

	first := cfg.GlobalPullBasedPermissions[0]
	if first.FromNamespace != "namespace-a" {
		t.Errorf("FromNamespace = %q, want %q", first.FromNamespace, "namespace-a")
	}
	if want := []string{"namespace-b", "namespace-c"}; !reflect.DeepEqual(first.ToNamespaces(), want) {
		t.Errorf("ToNamespaces() = %v, want %v", first.ToNamespaces(), want)
	}
	if first.ValidationPattern != "shoot-*" {
		t.Errorf("ValidationPattern = %q, want %q", first.ValidationPattern, "shoot-*")
	}
	if !first.AllowConfigMap || first.AllowSecret {
		t.Errorf("expected allowConfigMap=true, allowSecret=false, got %v/%v", first.AllowConfigMap, first.AllowSecret)
	}

	second := cfg.GlobalPullBasedPermissions[1]
	if !second.AllowSecret || second.AllowConfigMap {
		t.Errorf("expected allowSecret=true, allowConfigMap=false, got %v/%v", second.AllowSecret, second.AllowConfigMap)
	}
}

func TestLoadConfigWithoutGlobalPullBasedPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
defaults:
  type: string
  length: 32
`
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if len(cfg.GlobalPullBasedPermissions) != 0 {
		t.Errorf("expected no permissions, got %d", len(cfg.GlobalPullBasedPermissions))
	}
}

func TestLoadConfigInvalidGlobalPullBasedPermission(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Second entry is invalid (no kind allowed)
	configContent := `
globalPullBasedPermissions:
  - fromNamespace: "namespace-a"
    toNamespace: "namespace-b"
    validationPattern: "*"
    allowSecret: true
  - fromNamespace: "namespace-a"
    toNamespace: "namespace-b"
    validationPattern: "*"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err := LoadConfig(configPath)
	if err == nil {
		t.Fatal("LoadConfig() expected error for invalid permission, got nil")
	}
	if !strings.Contains(err.Error(), "globalPullBasedPermissions[1]") {
		t.Errorf("error should reference the invalid entry index, got: %v", err)
	}
}

func TestNewDefaultConfigConfigMapReplicatorEnabled(t *testing.T) {
	cfg := NewDefaultConfig()
	if !cfg.Features.ConfigMapReplicator {
		t.Error("expected ConfigMapReplicator feature to be enabled by default")
	}
}

func TestLoadConfigConfigMapReplicatorToggle(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
features:
  configMapReplicator: false
`
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if cfg.Features.ConfigMapReplicator {
		t.Error("expected ConfigMapReplicator feature to be disabled")
	}
	// Other features keep their defaults
	if !cfg.Features.SecretGenerator || !cfg.Features.SecretReplicator {
		t.Error("expected other features to remain enabled")
	}
}
