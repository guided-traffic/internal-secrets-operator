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
	"testing"
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
