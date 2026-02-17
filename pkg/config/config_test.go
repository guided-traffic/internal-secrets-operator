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
	"strings"
	"testing"
	"time"
)

func TestNewDefaultConfig(t *testing.T) {
	cfg := NewDefaultConfig()

	if cfg.Defaults.Type != DefaultType {
		t.Errorf("expected type %q, got %q", DefaultType, cfg.Defaults.Type)
	}
	if cfg.Defaults.Length != DefaultLength {
		t.Errorf("expected length %d, got %d", DefaultLength, cfg.Defaults.Length)
	}
	if !cfg.Defaults.String.Uppercase {
		t.Error("expected uppercase to be true")
	}
	if !cfg.Defaults.String.Lowercase {
		t.Error("expected lowercase to be true")
	}
	if !cfg.Defaults.String.Numbers {
		t.Error("expected numbers to be true")
	}
	if cfg.Defaults.String.SpecialChars {
		t.Error("expected specialChars to be false")
	}
	if cfg.Defaults.String.AllowedSpecialChars != DefaultAllowedSpecialChars {
		t.Errorf("expected allowedSpecialChars %q, got %q", DefaultAllowedSpecialChars, cfg.Defaults.String.AllowedSpecialChars)
	}
	// Test rotation defaults
	if cfg.Rotation.MinInterval.Duration() != DefaultRotationMinInterval {
		t.Errorf("expected rotation minInterval %v, got %v", DefaultRotationMinInterval, cfg.Rotation.MinInterval.Duration())
	}
	if cfg.Rotation.CreateEvents {
		t.Error("expected rotation createEvents to be false")
	}
	// Test feature defaults
	if !cfg.Features.SecretGenerator {
		t.Error("expected features.secretGenerator to be true")
	}
	if !cfg.Features.SecretReplicator {
		t.Error("expected features.secretReplicator to be true")
	}
}

func TestLoadConfigFileNotExists(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should return default config
	if cfg.Defaults.Type != DefaultType {
		t.Errorf("expected type %q, got %q", DefaultType, cfg.Defaults.Type)
	}
	if cfg.Defaults.Length != DefaultLength {
		t.Errorf("expected length %d, got %d", DefaultLength, cfg.Defaults.Length)
	}
}

func TestLoadConfigValidFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
defaults:
  type: bytes
  length: 64
  string:
    uppercase: true
    lowercase: false
    numbers: true
    specialChars: true
    allowedSpecialChars: "!@#"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Defaults.Type != "bytes" {
		t.Errorf("expected type %q, got %q", "bytes", cfg.Defaults.Type)
	}
	if cfg.Defaults.Length != 64 {
		t.Errorf("expected length %d, got %d", 64, cfg.Defaults.Length)
	}
	if !cfg.Defaults.String.Uppercase {
		t.Error("expected uppercase to be true")
	}
	if cfg.Defaults.String.Lowercase {
		t.Error("expected lowercase to be false")
	}
	if !cfg.Defaults.String.Numbers {
		t.Error("expected numbers to be true")
	}
	if !cfg.Defaults.String.SpecialChars {
		t.Error("expected specialChars to be true")
	}
	if cfg.Defaults.String.AllowedSpecialChars != "!@#" {
		t.Errorf("expected allowedSpecialChars %q, got %q", "!@#", cfg.Defaults.String.AllowedSpecialChars)
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write invalid YAML
	if err := os.WriteFile(configPath, []byte("invalid: yaml: content:"), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err := LoadConfig(configPath)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestLoadConfigUnreadableFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create a directory with the same name as the config file
	// This will cause os.ReadFile to fail
	if err := os.Mkdir(configPath, 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}

	_, err := LoadConfig(configPath)
	if err == nil {
		t.Error("expected error when config path is a directory, got nil")
	}
	if !strings.Contains(err.Error(), "failed to read config file") {
		t.Errorf("expected 'failed to read config file' error, got: %v", err)
	}
}

func TestLoadConfigAppliesDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write partial config - missing type and length
	configContent := `
defaults:
  string:
    uppercase: true
    lowercase: true
    numbers: true
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have defaults applied for missing values
	if cfg.Defaults.Type != DefaultType {
		t.Errorf("expected type %q, got %q", DefaultType, cfg.Defaults.Type)
	}
	if cfg.Defaults.Length != DefaultLength {
		t.Errorf("expected length %d, got %d", DefaultLength, cfg.Defaults.Length)
	}
	if cfg.Defaults.String.AllowedSpecialChars != DefaultAllowedSpecialChars {
		t.Errorf("expected allowedSpecialChars %q, got %q", DefaultAllowedSpecialChars, cfg.Defaults.String.AllowedSpecialChars)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid default config",
			config:    NewDefaultConfig(),
			wantError: false,
		},
		{
			name: "invalid type",
			config: &Config{
				Defaults: DefaultsConfig{
					Type:   "invalid",
					Length: 32,
					String: StringOptions{Uppercase: true},
				},
			},
			wantError: true,
			errorMsg:  "invalid default type",
		},
		{
			name: "invalid length",
			config: &Config{
				Defaults: DefaultsConfig{
					Type:   "string",
					Length: 0,
					String: StringOptions{Uppercase: true},
				},
			},
			wantError: true,
			errorMsg:  "default length must be positive",
		},
		{
			name: "negative length",
			config: &Config{
				Defaults: DefaultsConfig{
					Type:   "string",
					Length: -1,
					String: StringOptions{Uppercase: true},
				},
			},
			wantError: true,
			errorMsg:  "default length must be positive",
		},
		{
			name: "no charset options enabled",
			config: &Config{
				Defaults: DefaultsConfig{
					Type:   "string",
					Length: 32,
					String: StringOptions{
						Uppercase:    false,
						Lowercase:    false,
						Numbers:      false,
						SpecialChars: false,
					},
				},
			},
			wantError: true,
			errorMsg:  "at least one charset option must be enabled",
		},
		{
			name: "specialChars enabled but empty allowedSpecialChars",
			config: &Config{
				Defaults: DefaultsConfig{
					Type:   "string",
					Length: 32,
					String: StringOptions{
						SpecialChars:        true,
						AllowedSpecialChars: "",
					},
				},
			},
			wantError: true,
			errorMsg:  "allowedSpecialChars must not be empty",
		},
		{
			name: "valid bytes type",
			config: &Config{
				Defaults: DefaultsConfig{
					Type:   "bytes",
					Length: 32,
					String: StringOptions{Uppercase: true},
				},
			},
			wantError: false,
		},
		{
			name: "valid rsa type",
			config: &Config{
				Defaults: DefaultsConfig{
					Type:   "rsa",
					Length: 2048,
					String: StringOptions{Uppercase: true},
				},
			},
			wantError: false,
		},
		{
			name: "valid ecdsa type",
			config: &Config{
				Defaults: DefaultsConfig{
					Type:   "ecdsa",
					Length: 32,
					String: StringOptions{Uppercase: true},
				},
			},
			wantError: false,
		},
		{
			name: "valid ed25519 type",
			config: &Config{
				Defaults: DefaultsConfig{
					Type:   "ed25519",
					Length: 32,
					String: StringOptions{Uppercase: true},
				},
			},
			wantError: false,
		},
		{
			name: "valid with only numbers",
			config: &Config{
				Defaults: DefaultsConfig{
					Type:   "string",
					Length: 32,
					String: StringOptions{Numbers: true},
				},
			},
			wantError: false,
		},
		{
			name: "valid with only specialChars",
			config: &Config{
				Defaults: DefaultsConfig{
					Type:   "string",
					Length: 32,
					String: StringOptions{
						SpecialChars:        true,
						AllowedSpecialChars: "!@#",
					},
				},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestBuildCharset(t *testing.T) {
	tests := []struct {
		name     string
		options  StringOptions
		contains []string
		excludes []string
	}{
		{
			name: "all options enabled",
			options: StringOptions{
				Uppercase:           true,
				Lowercase:           true,
				Numbers:             true,
				SpecialChars:        true,
				AllowedSpecialChars: "!@#",
			},
			contains: []string{"a", "z", "A", "Z", "0", "9", "!", "@", "#"},
			excludes: []string{"$", "%"},
		},
		{
			name: "only lowercase",
			options: StringOptions{
				Lowercase: true,
			},
			contains: []string{"a", "z"},
			excludes: []string{"A", "Z", "0", "9", "!"},
		},
		{
			name: "only uppercase",
			options: StringOptions{
				Uppercase: true,
			},
			contains: []string{"A", "Z"},
			excludes: []string{"a", "z", "0", "9", "!"},
		},
		{
			name: "only numbers",
			options: StringOptions{
				Numbers: true,
			},
			contains: []string{"0", "9"},
			excludes: []string{"a", "z", "A", "Z", "!"},
		},
		{
			name: "only special chars",
			options: StringOptions{
				SpecialChars:        true,
				AllowedSpecialChars: "!@#$%",
			},
			contains: []string{"!", "@", "#", "$", "%"},
			excludes: []string{"a", "z", "A", "Z", "0", "9"},
		},
		{
			name: "lowercase and numbers",
			options: StringOptions{
				Lowercase: true,
				Numbers:   true,
			},
			contains: []string{"a", "z", "0", "9"},
			excludes: []string{"A", "Z", "!"},
		},
		{
			name: "nothing enabled",
			options: StringOptions{
				Uppercase:           false,
				Lowercase:           false,
				Numbers:             false,
				SpecialChars:        false,
				AllowedSpecialChars: "!@#",
			},
			contains: []string{},
			excludes: []string{"a", "A", "0", "!"},
		},
		{
			name: "special chars enabled but empty allowedSpecialChars",
			options: StringOptions{
				SpecialChars:        true,
				AllowedSpecialChars: "",
			},
			contains: []string{},
			excludes: []string{"!"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			charset := tt.options.BuildCharset()

			for _, c := range tt.contains {
				if len(charset) == 0 && len(tt.contains) > 0 {
					t.Errorf("charset is empty but expected to contain %q", c)
					continue
				}
				found := false
				for _, char := range charset {
					if string(char) == c {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("charset %q should contain %q", charset, c)
				}
			}

			for _, c := range tt.excludes {
				for _, char := range charset {
					if string(char) == c {
						t.Errorf("charset %q should not contain %q", charset, c)
						break
					}
				}
			}
		})
	}
}

func TestLoadConfigValidationError(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write config with all charset options disabled
	configContent := `
defaults:
  type: string
  length: 32
  string:
    uppercase: false
    lowercase: false
    numbers: false
    specialChars: false
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err := LoadConfig(configPath)
	if err == nil {
		t.Error("expected validation error, got nil")
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{
			name:     "empty string",
			input:    "",
			expected: 0,
			wantErr:  false,
		},
		{
			name:     "seconds",
			input:    "30s",
			expected: 30 * time.Second,
			wantErr:  false,
		},
		{
			name:     "minutes",
			input:    "5m",
			expected: 5 * time.Minute,
			wantErr:  false,
		},
		{
			name:     "hours",
			input:    "24h",
			expected: 24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "combined",
			input:    "1h30m",
			expected: 1*time.Hour + 30*time.Minute,
			wantErr:  false,
		},
		{
			name:     "days",
			input:    "7d",
			expected: 7 * 24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "fractional days",
			input:    "1.5d",
			expected: 36 * time.Hour,
			wantErr:  false,
		},
		{
			name:    "invalid duration",
			input:   "invalid",
			wantErr: true,
		},
		{
			name:    "invalid days format",
			input:   "abcd",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDuration(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestDurationUnmarshalYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
defaults:
  type: string
  length: 32
  string:
    uppercase: true
    lowercase: true
    numbers: true
rotation:
  minInterval: 10m
  createEvents: true
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Rotation.MinInterval.Duration() != 10*time.Minute {
		t.Errorf("expected minInterval 10m, got %v", cfg.Rotation.MinInterval.Duration())
	}
	if !cfg.Rotation.CreateEvents {
		t.Error("expected createEvents to be true")
	}
}

func TestLoadConfigRotationWithDays(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
defaults:
  type: string
  length: 32
  string:
    uppercase: true
    lowercase: true
    numbers: true
rotation:
  minInterval: 1d
  createEvents: false
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Rotation.MinInterval.Duration() != 24*time.Hour {
		t.Errorf("expected minInterval 24h (1d), got %v", cfg.Rotation.MinInterval.Duration())
	}
}

func TestLoadConfigRotationDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Config without rotation section - should use defaults
	configContent := `
defaults:
  type: string
  length: 32
  string:
    uppercase: true
    lowercase: true
    numbers: true
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Rotation.MinInterval.Duration() != DefaultRotationMinInterval {
		t.Errorf("expected default minInterval %v, got %v", DefaultRotationMinInterval, cfg.Rotation.MinInterval.Duration())
	}
	if cfg.Rotation.CreateEvents {
		t.Error("expected default createEvents to be false")
	}
}

func TestLoadConfigWithFeatureToggles(t *testing.T) {
	tests := []struct {
		name                     string
		configContent            string
		expectedSecretGenerator  bool
		expectedSecretReplicator bool
	}{
		{
			name: "both features enabled",
			configContent: `
features:
  secretGenerator: true
  secretReplicator: true
`,
			expectedSecretGenerator:  true,
			expectedSecretReplicator: true,
		},
		{
			name: "generator disabled, replicator enabled",
			configContent: `
features:
  secretGenerator: false
  secretReplicator: true
`,
			expectedSecretGenerator:  false,
			expectedSecretReplicator: true,
		},
		{
			name: "generator enabled, replicator disabled",
			configContent: `
features:
  secretGenerator: true
  secretReplicator: false
`,
			expectedSecretGenerator:  true,
			expectedSecretReplicator: false,
		},
		{
			name: "both features disabled",
			configContent: `
features:
  secretGenerator: false
  secretReplicator: false
`,
			expectedSecretGenerator:  false,
			expectedSecretReplicator: false,
		},
		{
			name: "features section omitted - should use defaults",
			configContent: `
defaults:
  type: string
  length: 32
`,
			expectedSecretGenerator:  true,
			expectedSecretReplicator: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")

			if err := os.WriteFile(configPath, []byte(tt.configContent), 0644); err != nil {
				t.Fatalf("failed to write config file: %v", err)
			}

			cfg, err := LoadConfig(configPath)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cfg.Features.SecretGenerator != tt.expectedSecretGenerator {
				t.Errorf("expected secretGenerator %v, got %v", tt.expectedSecretGenerator, cfg.Features.SecretGenerator)
			}
			if cfg.Features.SecretReplicator != tt.expectedSecretReplicator {
				t.Errorf("expected secretReplicator %v, got %v", tt.expectedSecretReplicator, cfg.Features.SecretReplicator)
			}
		})
	}
}

func TestDurationMarshalYAML(t *testing.T) {
	d := Duration(10 * time.Minute)

	result, err := d.MarshalYAML()
	if err != nil {
		t.Errorf("MarshalYAML() error = %v", err)
	}

	expected := "10m0s"
	if result != expected {
		t.Errorf("MarshalYAML() = %v, want %v", result, expected)
	}
}

func TestDurationUnmarshalYAMLError(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write config with invalid duration format
	configContent := `
defaults:
  type: string
  length: 32
  string:
    uppercase: true
    lowercase: true
    numbers: true
rotation:
  minInterval: "invalid-duration-format"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err := LoadConfig(configPath)
	if err == nil {
		t.Error("expected error for invalid duration format, got nil")
	}
}

func TestConfigValidateNegativeRotationMinInterval(t *testing.T) {
	cfg := NewDefaultConfig()
	cfg.Rotation.MinInterval = Duration(-5 * time.Minute)

	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for negative rotation minInterval, got nil")
	}
	if !strings.Contains(err.Error(), "rotation minInterval must be non-negative") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDurationUnmarshalYAMLParseError(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write config with invalid day format (not a number before 'd')
	configContent := `
defaults:
  type: string
  length: 32
  string:
    uppercase: true
    lowercase: true
    numbers: true
rotation:
  minInterval: "xyzd"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err := LoadConfig(configPath)
	if err == nil {
		t.Error("expected error for invalid day format duration, got nil")
	}
}

func TestDurationDurationMethod(t *testing.T) {
	d := Duration(15 * time.Minute)
	result := d.Duration()

	if result != 15*time.Minute {
		t.Errorf("expected 15m, got %v", result)
	}
}

func TestBuildCharsetAllOptions(t *testing.T) {
	tests := []struct {
		name             string
		opts             StringOptions
		expectedContains []string
		expectedNotEmpty bool
	}{
		{
			name: "only lowercase",
			opts: StringOptions{
				Lowercase: true,
			},
			expectedContains: []string{"a", "z"},
			expectedNotEmpty: true,
		},
		{
			name: "only uppercase",
			opts: StringOptions{
				Uppercase: true,
			},
			expectedContains: []string{"A", "Z"},
			expectedNotEmpty: true,
		},
		{
			name: "only numbers",
			opts: StringOptions{
				Numbers: true,
			},
			expectedContains: []string{"0", "9"},
			expectedNotEmpty: true,
		},
		{
			name: "special chars with custom allowed",
			opts: StringOptions{
				SpecialChars:        true,
				AllowedSpecialChars: "!@#",
			},
			expectedContains: []string{"!", "@", "#"},
			expectedNotEmpty: true,
		},
		{
			name: "special chars without allowed chars",
			opts: StringOptions{
				SpecialChars:        true,
				AllowedSpecialChars: "",
			},
			expectedNotEmpty: false, // Empty because AllowedSpecialChars is empty
		},
		{
			name: "all options enabled",
			opts: StringOptions{
				Lowercase:           true,
				Uppercase:           true,
				Numbers:             true,
				SpecialChars:        true,
				AllowedSpecialChars: "!@#",
			},
			expectedContains: []string{"a", "Z", "0", "!"},
			expectedNotEmpty: true,
		},
		{
			name: "all options disabled",
			opts: StringOptions{
				Lowercase:    false,
				Uppercase:    false,
				Numbers:      false,
				SpecialChars: false,
			},
			expectedNotEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			charset := tt.opts.BuildCharset()

			if tt.expectedNotEmpty && charset == "" {
				t.Error("expected non-empty charset")
			}

			if !tt.expectedNotEmpty && charset != "" {
				t.Errorf("expected empty charset, got %q", charset)
			}

			for _, s := range tt.expectedContains {
				if !strings.Contains(charset, s) {
					t.Errorf("expected charset to contain %q, got %q", s, charset)
				}
			}
		})
	}
}

func TestConfigValidateSpecialCharsEnabledButEmpty(t *testing.T) {
	cfg := NewDefaultConfig()
	cfg.Defaults.String.SpecialChars = true
	cfg.Defaults.String.AllowedSpecialChars = ""

	err := cfg.Validate()
	if err == nil {
		t.Error("expected error when specialChars is enabled but allowedSpecialChars is empty")
	}
	if !strings.Contains(err.Error(), "allowedSpecialChars must not be empty") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestConfigValidateBytesType(t *testing.T) {
	cfg := NewDefaultConfig()
	cfg.Defaults.Type = "bytes"

	err := cfg.Validate()
	if err != nil {
		t.Errorf("unexpected error for 'bytes' type: %v", err)
	}
}

func TestLoadConfigAppliesDefaultsForEmptyValues(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write config with empty/zero values that should get defaults
	configContent := `
defaults:
  type: ""
  length: 0
  string:
    uppercase: true
    lowercase: true
    numbers: true
    allowedSpecialChars: ""
rotation:
  minInterval: 0
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have defaults applied for empty/zero values
	if cfg.Defaults.Type != DefaultType {
		t.Errorf("expected type %q, got %q", DefaultType, cfg.Defaults.Type)
	}
	if cfg.Defaults.Length != DefaultLength {
		t.Errorf("expected length %d, got %d", DefaultLength, cfg.Defaults.Length)
	}
	if cfg.Defaults.String.AllowedSpecialChars != DefaultAllowedSpecialChars {
		t.Errorf("expected allowedSpecialChars %q, got %q", DefaultAllowedSpecialChars, cfg.Defaults.String.AllowedSpecialChars)
	}
	if cfg.Rotation.MinInterval.Duration() != DefaultRotationMinInterval {
		t.Errorf("expected rotation minInterval %v, got %v", DefaultRotationMinInterval, cfg.Rotation.MinInterval.Duration())
	}
}
