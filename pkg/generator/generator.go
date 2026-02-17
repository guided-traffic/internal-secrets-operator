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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/guided-traffic/internal-secrets-operator/pkg/config"
)

// Generator defines the interface for secret generation
type Generator interface {
	// GenerateString generates a random string of the specified length
	GenerateString(length int) (string, error)
	// GenerateStringWithCharset generates a random string with a custom charset
	GenerateStringWithCharset(length int, charset string) (string, error)
	// GenerateBytes generates random bytes of the specified length
	GenerateBytes(length int) ([]byte, error)
	// GenerateRSAKeypair generates an RSA keypair with the given key size in bits.
	// Returns (privateKeyPEM, publicKeyPEM, error).
	GenerateRSAKeypair(bits int) (string, string, error)
	// GenerateECDSAKeypair generates an ECDSA keypair for the given curve name.
	// Supported curves: P-256, P-384, P-521.
	// Returns (privateKeyPEM, publicKeyPEM, error).
	GenerateECDSAKeypair(curveName string) (string, string, error)
	// GenerateEd25519Keypair generates an Ed25519 keypair.
	// Returns (privateKeyPEM, publicKeyPEM, error).
	GenerateEd25519Keypair() (string, string, error)
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
	case config.DefaultType, "":
		return g.GenerateStringWithCharset(length, charset)
	case config.TypeBytes:
		bytes, err := g.GenerateBytes(length)
		if err != nil {
			return "", err
		}
		return string(bytes), nil
	case config.TypeRSA, config.TypeECDSA, config.TypeEd25519:
		return "", fmt.Errorf("keypair types must be generated using dedicated keypair methods, not GenerateWithCharset")
	default:
		return "", fmt.Errorf("unknown generation type: %s", genType)
	}
}

// GenerateRSAKeypair generates an RSA keypair with the given key size in bits.
// Returns the private key and public key in PKCS#1 PEM format.
func (g *SecretGenerator) GenerateRSAKeypair(bits int) (string, string, error) {
	if bits < 1024 {
		return "", "", fmt.Errorf("RSA key size must be at least 1024 bits, got %d", bits)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode private key in PKCS#1 PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Encode public key in PKCS#1 PEM format
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	})

	return string(privateKeyPEM), string(publicKeyPEM), nil
}

// GenerateECDSAKeypair generates an ECDSA keypair for the given curve name.
// Returns the private key in EC PEM format and public key in PKIX PEM format.
func (g *SecretGenerator) GenerateECDSAKeypair(curveName string) (string, string, error) {
	curve, err := parseCurve(curveName)
	if err != nil {
		return "", "", err
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	// Encode private key in EC PEM format (SEC 1 / RFC 5915)
	ecPrivateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal ECDSA private key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecPrivateKeyBytes,
	})

	// Encode public key in PKIX PEM format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal ECDSA public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(privateKeyPEM), string(publicKeyPEM), nil
}

// GenerateEd25519Keypair generates an Ed25519 keypair.
// Returns the private key and public key in PKCS#8/PKIX PEM format.
func (g *SecretGenerator) GenerateEd25519Keypair() (string, string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	// Encode private key in PKCS#8 PEM format
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal Ed25519 private key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})

	// Encode public key in PKIX PEM format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal Ed25519 public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(privateKeyPEM), string(publicKeyPEM), nil
}

// parseCurve parses a curve name string into an elliptic.Curve
func parseCurve(curveName string) (elliptic.Curve, error) {
	switch curveName {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported ECDSA curve: %s, must be 'P-256', 'P-384', or 'P-521'", curveName)
	}
}
