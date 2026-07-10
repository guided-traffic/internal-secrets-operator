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
	"slices"

	"github.com/guided-traffic/internal-secrets-operator/pkg/config"
)

// ObjectKind identifies the kind of object being replicated
type ObjectKind string

const (
	// KindSecret identifies Secrets
	KindSecret ObjectKind = "Secret"
	// KindConfigMap identifies ConfigMaps
	KindConfigMap ObjectKind = "ConfigMap"
)

// allowsKind checks if a permission applies to the given object kind
func allowsKind(p *config.GlobalPullBasedPermission, kind ObjectKind) bool {
	switch kind {
	case KindSecret:
		return p.AllowSecret
	case KindConfigMap:
		return p.AllowConfigMap
	default:
		return false
	}
}

// IsGloballyAllowed checks if a global pull-based permission grants replication
// of the source object into the target namespace. Namespaces are matched
// exactly; the source object name is matched against the glob validationPattern.
func IsGloballyAllowed(perms []config.GlobalPullBasedPermission, kind ObjectKind, sourceNamespace, sourceName, targetNamespace string) (bool, error) {
	for i := range perms {
		p := &perms[i]
		if !allowsKind(p, kind) {
			continue
		}
		if !slices.Contains(p.FromNamespaces(), sourceNamespace) {
			continue
		}
		if !slices.Contains(p.ToNamespaces(), targetNamespace) {
			continue
		}
		matched, err := filepath.Match(p.ValidationPattern, sourceName)
		if err != nil {
			return false, fmt.Errorf("invalid glob pattern %q in global pull-based permission: %w", p.ValidationPattern, err)
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

// ValidatePullConsent checks whether pull-based replication is allowed, either by
// the source-side allowlist annotation (mutual consent) or by a global
// pull-based permission from the operator configuration.
// Returns whether replication is allowed and, if denied, a human-readable reason.
func ValidatePullConsent(perms []config.GlobalPullBasedPermission, kind ObjectKind, sourceNamespace, sourceName, sourceAllowlist, targetNamespace string) (bool, string) {
	allowed, annotErr := ValidateReplication(sourceNamespace, sourceAllowlist, targetNamespace)
	if allowed {
		return true, ""
	}

	globallyAllowed, globalErr := IsGloballyAllowed(perms, kind, sourceNamespace, sourceName, targetNamespace)
	if globalErr != nil {
		return false, fmt.Sprintf("%v; global pull-based permission check failed: %v", annotErr, globalErr)
	}
	if globallyAllowed {
		return true, ""
	}
	return false, fmt.Sprintf("%v; no global pull-based permission matches", annotErr)
}

// MatchesAnyGlobalSource checks if an object could be the source of any global
// pull-based permission, regardless of target namespace. Used by watch
// predicates to trigger target reconciliation when such a source changes.
func MatchesAnyGlobalSource(perms []config.GlobalPullBasedPermission, kind ObjectKind, sourceNamespace, sourceName string) bool {
	for i := range perms {
		p := &perms[i]
		if !allowsKind(p, kind) {
			continue
		}
		if !slices.Contains(p.FromNamespaces(), sourceNamespace) {
			continue
		}
		// Invalid patterns are rejected at startup by config validation
		if matched, err := filepath.Match(p.ValidationPattern, sourceName); err == nil && matched {
			return true
		}
	}
	return false
}
