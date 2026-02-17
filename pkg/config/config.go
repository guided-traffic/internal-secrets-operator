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

// Package config provides configuration types and validation for the internal-secrets-operator.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultConfigPath is the default path to the configuration file
	DefaultConfigPath = "/etc/secret-operator/config.yaml"

	// DefaultType is the default generation type
	DefaultType = "string"

	// TypeBytes is the bytes generation type
	TypeBytes = "bytes"

	// TypeRSA is the RSA keypair generation type
	TypeRSA = "rsa"

	// TypeECDSA is the ECDSA keypair generation type
	TypeECDSA = "ecdsa"

	// TypeEd25519 is the Ed25519 keypair generation type
	TypeEd25519 = "ed25519"

	// DefaultRSAKeySize is the default RSA key size in bits
	DefaultRSAKeySize = 2048

	// DefaultECDSACurve is the default ECDSA curve
	DefaultECDSACurve = "P-256"

	// DefaultLength is the default length for generated values
	DefaultLength = 32

	// DefaultAllowedSpecialChars is the default set of special characters
	DefaultAllowedSpecialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

	// DefaultRotationMinInterval is the minimum allowed rotation interval
	DefaultRotationMinInterval = 5 * time.Minute
)

// Config holds the operator configuration
type Config struct {
	Defaults DefaultsConfig `yaml:"defaults"`
	Rotation RotationConfig `yaml:"rotation"`
	Features FeaturesConfig `yaml:"features"`
}

// FeaturesConfig holds feature toggle configuration
type FeaturesConfig struct {
	SecretGenerator  bool `yaml:"secretGenerator"`
	SecretReplicator bool `yaml:"secretReplicator"`
}

// DefaultsConfig holds the default values for secret generation
type DefaultsConfig struct {
	Type   string        `yaml:"type"`
	Length int           `yaml:"length"`
	String StringOptions `yaml:"string"`
}

// RotationConfig holds the configuration for secret rotation
type RotationConfig struct {
	MinInterval        Duration                 `yaml:"minInterval"`
	CreateEvents       bool                     `yaml:"createEvents"`
	MaintenanceWindows MaintenanceWindowsConfig `yaml:"maintenanceWindows"`
}

// MaintenanceWindowsConfig holds the configuration for maintenance windows
type MaintenanceWindowsConfig struct {
	Enabled bool                `yaml:"enabled"`
	Windows []MaintenanceWindow `yaml:"windows"`
}

// MaintenanceWindow defines a time window during which secret rotation is allowed
type MaintenanceWindow struct {
	Name      string   `yaml:"name"`
	Days      []string `yaml:"days"`
	StartTime string   `yaml:"startTime"`
	EndTime   string   `yaml:"endTime"`
	Timezone  string   `yaml:"timezone"`
}

// StringOptions holds the character set options for string generation
type StringOptions struct {
	Uppercase           bool   `yaml:"uppercase"`
	Lowercase           bool   `yaml:"lowercase"`
	Numbers             bool   `yaml:"numbers"`
	SpecialChars        bool   `yaml:"specialChars"`
	AllowedSpecialChars string `yaml:"allowedSpecialChars"`
}

// Duration is a wrapper around time.Duration that supports YAML unmarshaling
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler for Duration
func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	duration, err := ParseDuration(s)
	if err != nil {
		return err
	}

	*d = Duration(duration)
	return nil
}

// MarshalYAML implements yaml.Marshaler for Duration
func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

// Duration returns the time.Duration value
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// ParseDuration parses a duration string with support for day suffix (d)
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}

	// Handle day suffix by converting to hours
	// e.g., "7d" -> "168h"
	if len(s) > 1 && s[len(s)-1] == 'd' {
		// Parse the number of days
		daysStr := s[:len(s)-1]
		var days float64
		if _, err := fmt.Sscanf(daysStr, "%f", &days); err != nil {
			return 0, fmt.Errorf("invalid duration: %s", s)
		}
		return time.Duration(days * 24 * float64(time.Hour)), nil
	}

	return time.ParseDuration(s)
}

// NewDefaultConfig creates a Config with default values
func NewDefaultConfig() *Config {
	return &Config{
		Defaults: DefaultsConfig{
			Type:   DefaultType,
			Length: DefaultLength,
			String: StringOptions{
				Uppercase:           true,
				Lowercase:           true,
				Numbers:             true,
				SpecialChars:        false,
				AllowedSpecialChars: DefaultAllowedSpecialChars,
			},
		},
		Rotation: RotationConfig{
			MinInterval:  Duration(DefaultRotationMinInterval),
			CreateEvents: false,
		},
		Features: FeaturesConfig{
			SecretGenerator:  true,
			SecretReplicator: true,
		},
	}
}

// LoadConfig loads configuration from a YAML file.
// If the file does not exist, it returns the default configuration.
func LoadConfig(path string) (*Config, error) {
	config := NewDefaultConfig()

	// Clean the path to prevent directory traversal
	cleanPath := filepath.Clean(path)

	// Check if file exists
	if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
		return config, nil
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Apply defaults for zero values
	if config.Defaults.Type == "" {
		config.Defaults.Type = DefaultType
	}
	if config.Defaults.Length == 0 {
		config.Defaults.Length = DefaultLength
	}
	if config.Defaults.String.AllowedSpecialChars == "" {
		config.Defaults.String.AllowedSpecialChars = DefaultAllowedSpecialChars
	}
	// Apply defaults for rotation config
	if config.Rotation.MinInterval == 0 {
		config.Rotation.MinInterval = Duration(DefaultRotationMinInterval)
	}

	// Validate the configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate generation type
	switch c.Defaults.Type {
	case DefaultType, TypeBytes, TypeRSA, TypeECDSA, TypeEd25519:
		// valid types
	default:
		return fmt.Errorf("invalid default type: %s, must be 'string', 'bytes', 'rsa', 'ecdsa', or 'ed25519'", c.Defaults.Type)
	}

	// Validate length
	if c.Defaults.Length <= 0 {
		return fmt.Errorf("default length must be positive, got %d", c.Defaults.Length)
	}

	// Validate that at least one charset option is enabled for string type
	if !c.Defaults.String.Uppercase && !c.Defaults.String.Lowercase &&
		!c.Defaults.String.Numbers && !c.Defaults.String.SpecialChars {
		return fmt.Errorf("at least one charset option must be enabled (uppercase, lowercase, numbers, or specialChars)")
	}

	// Validate that if specialChars is enabled, allowedSpecialChars is not empty
	if c.Defaults.String.SpecialChars && c.Defaults.String.AllowedSpecialChars == "" {
		return fmt.Errorf("allowedSpecialChars must not be empty when specialChars is enabled")
	}

	// Validate rotation minInterval
	if c.Rotation.MinInterval.Duration() < 0 {
		return fmt.Errorf("rotation minInterval must be non-negative, got %s", c.Rotation.MinInterval.Duration())
	}

	// Validate maintenance windows if enabled
	if c.Rotation.MaintenanceWindows.Enabled {
		if err := c.Rotation.MaintenanceWindows.Validate(); err != nil {
			return fmt.Errorf("maintenance windows configuration error: %w", err)
		}
	}

	return nil
}

// BuildCharset builds the character set string based on the StringOptions
func (s *StringOptions) BuildCharset() string {
	var charset string

	if s.Lowercase {
		charset += "abcdefghijklmnopqrstuvwxyz"
	}
	if s.Uppercase {
		charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if s.Numbers {
		charset += "0123456789"
	}
	if s.SpecialChars && s.AllowedSpecialChars != "" {
		charset += s.AllowedSpecialChars
	}

	return charset
}
