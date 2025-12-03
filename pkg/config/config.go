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
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultConfigPath is the default path to the configuration file
	DefaultConfigPath = "/etc/secret-operator/config.yaml"

	// DefaultType is the default generation type
	DefaultType = "string"

	// DefaultLength is the default length for generated values
	DefaultLength = 32

	// DefaultAllowedSpecialChars is the default set of special characters
	DefaultAllowedSpecialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
)

// Config holds the operator configuration
type Config struct {
	Defaults DefaultsConfig `yaml:"defaults"`
}

// DefaultsConfig holds the default values for secret generation
type DefaultsConfig struct {
	Type   string        `yaml:"type"`
	Length int           `yaml:"length"`
	String StringOptions `yaml:"string"`
}

// StringOptions holds the character set options for string generation
type StringOptions struct {
	Uppercase           bool   `yaml:"uppercase"`
	Lowercase           bool   `yaml:"lowercase"`
	Numbers             bool   `yaml:"numbers"`
	SpecialChars        bool   `yaml:"specialChars"`
	AllowedSpecialChars string `yaml:"allowedSpecialChars"`
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
	}
}

// LoadConfig loads configuration from a YAML file.
// If the file does not exist, it returns the default configuration.
func LoadConfig(path string) (*Config, error) {
	config := NewDefaultConfig()

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return config, nil
	}

	data, err := os.ReadFile(path)
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
	case "string", "bytes":
		// valid types
	default:
		return fmt.Errorf("invalid default type: %s, must be 'string' or 'bytes'", c.Defaults.Type)
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
