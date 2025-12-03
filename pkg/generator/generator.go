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

package generator

import (
	"crypto/rand"
	"fmt"
)

// Generator defines the interface for secret generation
type Generator interface {
	// GenerateString generates a random string of the specified length
	GenerateString(length int) (string, error)
	// GenerateStringWithCharset generates a random string with a custom charset
	GenerateStringWithCharset(length int, charset string) (string, error)
	// GenerateBytes generates random bytes of the specified length
	GenerateBytes(length int) ([]byte, error)
	// Generate generates a value based on the specified type
	Generate(genType string, length int) (string, error)
	// GenerateWithCharset generates a value based on the specified type with a custom charset
	GenerateWithCharset(genType string, length int, charset string) (string, error)
}

// SecretGenerator implements the Generator interface using crypto/rand
type SecretGenerator struct {
	// defaultCharset is the default character set used for string generation
	defaultCharset string
}

// DefaultCharset is the default character set for generating random strings
const DefaultCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"

// AlphanumericCharset contains only alphanumeric characters
const AlphanumericCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// NewSecretGenerator creates a new SecretGenerator with default settings
func NewSecretGenerator() *SecretGenerator {
	return &SecretGenerator{
		defaultCharset: AlphanumericCharset,
	}
}

// NewSecretGeneratorWithCharset creates a new SecretGenerator with a custom default charset
func NewSecretGeneratorWithCharset(charset string) *SecretGenerator {
	return &SecretGenerator{
		defaultCharset: charset,
	}
}

// GenerateString generates a random string of the specified length using the default charset
func (g *SecretGenerator) GenerateString(length int) (string, error) {
	return g.GenerateStringWithCharset(length, g.defaultCharset)
}

// GenerateStringWithCharset generates a random string of the specified length using a custom charset
func (g *SecretGenerator) GenerateStringWithCharset(length int, charset string) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("length must be positive, got %d", length)
	}
	if charset == "" {
		return "", fmt.Errorf("charset must not be empty")
	}

	result := make([]byte, length)
	charsetLen := len(charset)

	// Generate random bytes
	randomBytes := make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Map random bytes to charset characters
	for i := 0; i < length; i++ {
		result[i] = charset[int(randomBytes[i])%charsetLen]
	}

	return string(result), nil
}

// GenerateBytes generates random bytes of the specified length
func (g *SecretGenerator) GenerateBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("length must be positive, got %d", length)
	}

	randomBytes := make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return randomBytes, nil
}

// Generate generates a value based on the specified type using the default charset
func (g *SecretGenerator) Generate(genType string, length int) (string, error) {
	return g.GenerateWithCharset(genType, length, g.defaultCharset)
}

// GenerateWithCharset generates a value based on the specified type with a custom charset
func (g *SecretGenerator) GenerateWithCharset(genType string, length int, charset string) (string, error) {
	switch genType {
	case "string", "":
		return g.GenerateStringWithCharset(length, charset)
	case "bytes":
		bytes, err := g.GenerateBytes(length)
		if err != nil {
			return "", err
		}
		return string(bytes), nil
	default:
		return "", fmt.Errorf("unknown generation type: %s", genType)
	}
}
