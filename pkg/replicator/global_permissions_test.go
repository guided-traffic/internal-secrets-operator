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
	"strings"
	"testing"

	"github.com/guided-traffic/internal-secrets-operator/pkg/config"
)

func TestIsGloballyAllowed(t *testing.T) {
	perms := []config.GlobalPullBasedPermission{
		{
			FromNamespace:     "garden",
			ToNamespace:       "shoot-a,shoot-b",
			ValidationPattern: "ca-*",
			AllowConfigMap:    true,
		},
		{
			FromNamespace:     "prod-1, prod-2",
			ToNamespace:       "staging",
			ValidationPattern: "db-credentials",
			AllowSecret:       true,
		},
	}

	tests := []struct {
		name            string
		perms           []config.GlobalPullBasedPermission
		kind            ObjectKind
		sourceNamespace string
		sourceName      string
		targetNamespace string
		want            bool
		wantErr         bool
	}{
		{
			name:            "configmap allowed by first permission",
			perms:           perms,
			kind:            KindConfigMap,
			sourceNamespace: "garden",
			sourceName:      "ca-bundle",
			targetNamespace: "shoot-a",
			want:            true,
		},
		{
			name:            "configmap allowed for second target namespace",
			perms:           perms,
			kind:            KindConfigMap,
			sourceNamespace: "garden",
			sourceName:      "ca-bundle",
			targetNamespace: "shoot-b",
			want:            true,
		},
		{
			name:            "secret denied by first permission (kind mismatch)",
			perms:           perms,
			kind:            KindSecret,
			sourceNamespace: "garden",
			sourceName:      "ca-bundle",
			targetNamespace: "shoot-a",
			want:            false,
		},
		{
			name:            "secret allowed by second permission with whitespace in list",
			perms:           perms,
			kind:            KindSecret,
			sourceNamespace: "prod-2",
			sourceName:      "db-credentials",
			targetNamespace: "staging",
			want:            true,
		},
		{
			name:            "denied - source namespace not in list",
			perms:           perms,
			kind:            KindConfigMap,
			sourceNamespace: "other",
			sourceName:      "ca-bundle",
			targetNamespace: "shoot-a",
			want:            false,
		},
		{
			name:            "denied - target namespace not in list",
			perms:           perms,
			kind:            KindConfigMap,
			sourceNamespace: "garden",
			sourceName:      "ca-bundle",
			targetNamespace: "shoot-c",
			want:            false,
		},
		{
			name:            "denied - source name does not match pattern",
			perms:           perms,
			kind:            KindConfigMap,
			sourceNamespace: "garden",
			sourceName:      "other-bundle",
			targetNamespace: "shoot-a",
			want:            false,
		},
		{
			name:            "denied - namespace lists are matched exactly, not as pattern",
			perms:           perms,
			kind:            KindConfigMap,
			sourceNamespace: "garden-2",
			sourceName:      "ca-bundle",
			targetNamespace: "shoot-a",
			want:            false,
		},
		{
			name:            "no permissions configured",
			perms:           nil,
			kind:            KindSecret,
			sourceNamespace: "garden",
			sourceName:      "anything",
			targetNamespace: "staging",
			want:            false,
		},
		{
			name: "wildcard pattern matches all names",
			perms: []config.GlobalPullBasedPermission{
				{
					FromNamespace:     "garden",
					ToNamespace:       "staging",
					ValidationPattern: "*",
					AllowSecret:       true,
					AllowConfigMap:    true,
				},
			},
			kind:            KindSecret,
			sourceNamespace: "garden",
			sourceName:      "any-name",
			targetNamespace: "staging",
			want:            true,
		},
		{
			name: "character class pattern",
			perms: []config.GlobalPullBasedPermission{
				{
					FromNamespace:     "garden",
					ToNamespace:       "staging",
					ValidationPattern: "cert-[0-9]",
					AllowSecret:       true,
				},
			},
			kind:            KindSecret,
			sourceNamespace: "garden",
			sourceName:      "cert-5",
			targetNamespace: "staging",
			want:            true,
		},
		{
			name: "invalid pattern returns error",
			perms: []config.GlobalPullBasedPermission{
				{
					FromNamespace:     "garden",
					ToNamespace:       "staging",
					ValidationPattern: "[a-",
					AllowSecret:       true,
				},
			},
			kind:            KindSecret,
			sourceNamespace: "garden",
			sourceName:      "anything",
			targetNamespace: "staging",
			want:            false,
			wantErr:         true,
		},
		{
			name: "unknown kind never matches",
			perms: []config.GlobalPullBasedPermission{
				{
					FromNamespace:     "garden",
					ToNamespace:       "staging",
					ValidationPattern: "*",
					AllowSecret:       true,
					AllowConfigMap:    true,
				},
			},
			kind:            ObjectKind("Pod"),
			sourceNamespace: "garden",
			sourceName:      "anything",
			targetNamespace: "staging",
			want:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsGloballyAllowed(tt.perms, tt.kind, tt.sourceNamespace, tt.sourceName, tt.targetNamespace)
			if (err != nil) != tt.wantErr {
				t.Fatalf("IsGloballyAllowed() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("IsGloballyAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchesAnyGlobalSource(t *testing.T) {
	perms := []config.GlobalPullBasedPermission{
		{
			FromNamespace:     "garden",
			ToNamespace:       "shoot-a",
			ValidationPattern: "ca-*",
			AllowConfigMap:    true,
		},
	}

	tests := []struct {
		name            string
		kind            ObjectKind
		sourceNamespace string
		sourceName      string
		want            bool
	}{
		{"matching configmap source", KindConfigMap, "garden", "ca-bundle", true},
		{"kind not allowed", KindSecret, "garden", "ca-bundle", false},
		{"namespace not covered", KindConfigMap, "other", "ca-bundle", false},
		{"name does not match pattern", KindConfigMap, "garden", "other", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesAnyGlobalSource(perms, tt.kind, tt.sourceNamespace, tt.sourceName)
			if got != tt.want {
				t.Errorf("MatchesAnyGlobalSource() = %v, want %v", got, tt.want)
			}
		})
	}

	if MatchesAnyGlobalSource(nil, KindConfigMap, "garden", "ca-bundle") {
		t.Error("MatchesAnyGlobalSource() with no permissions should be false")
	}
}

func TestValidatePullConsent(t *testing.T) {
	perms := []config.GlobalPullBasedPermission{
		{
			FromNamespace:     "production",
			ToNamespace:       "staging",
			ValidationPattern: "db-*",
			AllowSecret:       true,
		},
	}

	tests := []struct {
		name            string
		perms           []config.GlobalPullBasedPermission
		kind            ObjectKind
		sourceNamespace string
		sourceName      string
		sourceAllowlist string
		targetNamespace string
		wantAllowed     bool
		reasonContains  string
	}{
		{
			name:            "allowed by annotation",
			perms:           nil,
			kind:            KindSecret,
			sourceNamespace: "production",
			sourceName:      "db-credentials",
			sourceAllowlist: "staging",
			targetNamespace: "staging",
			wantAllowed:     true,
		},
		{
			name:            "allowed by global permission without annotation",
			perms:           perms,
			kind:            KindSecret,
			sourceNamespace: "production",
			sourceName:      "db-credentials",
			sourceAllowlist: "",
			targetNamespace: "staging",
			wantAllowed:     true,
		},
		{
			name:            "allowed by global permission when annotation denies",
			perms:           perms,
			kind:            KindSecret,
			sourceNamespace: "production",
			sourceName:      "db-credentials",
			sourceAllowlist: "other-namespace",
			targetNamespace: "staging",
			wantAllowed:     true,
		},
		{
			name:            "denied - no annotation, no matching permission",
			perms:           perms,
			kind:            KindSecret,
			sourceNamespace: "production",
			sourceName:      "app-secret",
			sourceAllowlist: "",
			targetNamespace: "staging",
			wantAllowed:     false,
			reasonContains:  "no global pull-based permission matches",
		},
		{
			name:            "denied - kind not allowed by permission",
			perms:           perms,
			kind:            KindConfigMap,
			sourceNamespace: "production",
			sourceName:      "db-config",
			sourceAllowlist: "",
			targetNamespace: "staging",
			wantAllowed:     false,
			reasonContains:  "no global pull-based permission matches",
		},
		{
			name:            "denied reason includes annotation error",
			perms:           nil,
			kind:            KindSecret,
			sourceNamespace: "production",
			sourceName:      "db-credentials",
			sourceAllowlist: "",
			targetNamespace: "staging",
			wantAllowed:     false,
			reasonContains:  AnnotationReplicatableFromNamespaces,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := ValidatePullConsent(tt.perms, tt.kind, tt.sourceNamespace, tt.sourceName, tt.sourceAllowlist, tt.targetNamespace)
			if allowed != tt.wantAllowed {
				t.Fatalf("ValidatePullConsent() allowed = %v, want %v (reason: %s)", allowed, tt.wantAllowed, reason)
			}
			if tt.wantAllowed && reason != "" {
				t.Errorf("expected empty reason when allowed, got %q", reason)
			}
			if !tt.wantAllowed && tt.reasonContains != "" && !strings.Contains(reason, tt.reasonContains) {
				t.Errorf("reason = %q, expected to contain %q", reason, tt.reasonContains)
			}
		})
	}
}
