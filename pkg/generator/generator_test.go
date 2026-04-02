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
	"crypto/mlkem"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSecretGenerator(t *testing.T) {
	gen := NewSecretGenerator()
	require.NotNil(t, gen, "NewSecretGenerator returned nil")
	assert.Equal(t, AlphanumericCharset, gen.defaultCharset)
}

func TestNewSecretGeneratorWithCharset(t *testing.T) {
	customCharset := "abc123"
	gen := NewSecretGeneratorWithCharset(customCharset)
	require.NotNil(t, gen, "NewSecretGeneratorWithCharset returned nil")
	assert.Equal(t, customCharset, gen.defaultCharset)
}

func TestGenerateString(t *testing.T) {
	tests := []struct {
		name      string
		length    int
		wantError bool
	}{
		{"length 1", 1, false},
		{"length 16", 16, false},
		{"length 32", 32, false},
		{"length 64", 64, false},
		{"length 128", 128, false},
		{"zero length", 0, true},
		{"negative length", -1, true},
	}

	gen := NewSecretGenerator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := gen.GenerateString(tt.length)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(result) != tt.length {
				t.Errorf("expected length %d, got %d", tt.length, len(result))
			}

			// Verify all characters are from the charset
			for _, c := range result {
				if !strings.ContainsRune(gen.defaultCharset, c) {
					t.Errorf("result contains character %q not in charset", c)
				}
			}
		})
	}
}

func TestGenerateStringUniqueness(t *testing.T) {
	gen := NewSecretGenerator()
	iterations := 100
	results := make(map[string]bool)

	for i := 0; i < iterations; i++ {
		result, err := gen.GenerateString(32)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if results[result] {
			t.Errorf("duplicate result generated: %s", result)
		}
		results[result] = true
	}
}

func TestGenerateBytes(t *testing.T) {
	tests := []struct {
		name      string
		length    int
		wantError bool
	}{
		{"length 16", 16, false},
		{"length 32", 32, false},
		{"zero length", 0, true},
		{"negative length", -1, true},
	}

	gen := NewSecretGenerator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := gen.GenerateBytes(tt.length)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Verify the byte slice has the expected length
			if len(result) != tt.length {
				t.Errorf("expected length %d, got %d", tt.length, len(result))
			}
		})
	}
}

func TestGenerate(t *testing.T) {
	gen := NewSecretGenerator()

	tests := []struct {
		name      string
		genType   string
		length    int
		wantError bool
	}{
		{"string type", "string", 32, false},
		{"empty type defaults to string", "", 32, false},
		{"bytes type", "bytes", 32, false},
		{"unknown type", "unknown", 32, true},
		{"rsa type errors via Generate", "rsa", 2048, true},
		{"ecdsa type errors via Generate", "ecdsa", 256, true},
		{"ed25519 type errors via Generate", "ed25519", 256, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := gen.Generate(tt.genType, tt.length)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result == "" {
				t.Error("expected non-empty result")
			}
		})
	}
}

func BenchmarkGenerateString(b *testing.B) {
	gen := NewSecretGenerator()
	for i := 0; i < b.N; i++ {
		_, _ = gen.GenerateString(32)
	}
}

func BenchmarkGenerateBytes(b *testing.B) {
	gen := NewSecretGenerator()
	for i := 0; i < b.N; i++ {
		_, _ = gen.GenerateBytes(32)
	}
}

func TestGenerateStringWithCharset(t *testing.T) {
	gen := NewSecretGenerator()

	tests := []struct {
		name      string
		length    int
		charset   string
		wantError bool
	}{
		{"valid charset", 16, "abc123", false},
		{"single char charset", 10, "a", false},
		{"empty charset", 16, "", true},
		{"zero length", 0, "abc", true},
		{"negative length", -1, "abc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := gen.GenerateStringWithCharset(tt.length, tt.charset)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(result) != tt.length {
				t.Errorf("expected length %d, got %d", tt.length, len(result))
			}

			// Verify all characters are from the charset
			for _, c := range result {
				if !strings.ContainsRune(tt.charset, c) {
					t.Errorf("result contains character %q not in charset %q", c, tt.charset)
				}
			}
		})
	}
}

func TestGenerateWithCharset(t *testing.T) {
	gen := NewSecretGenerator()

	tests := []struct {
		name      string
		genType   string
		length    int
		charset   string
		wantError bool
	}{
		{"string type with custom charset", "string", 16, "abc123", false},
		{"empty type defaults to string", "", 16, "abc123", false},
		{"bytes type ignores charset", "bytes", 16, "abc123", false},
		{"unknown type", "invalid", 16, "abc123", true},
		{"string with empty charset", "string", 16, "", true},
		{"zero length string", "string", 0, "abc", true},
		{"zero length bytes", "bytes", 0, "abc", true},
		{"rsa type errors via GenerateWithCharset", "rsa", 2048, "abc", true},
		{"ecdsa type errors via GenerateWithCharset", "ecdsa", 256, "abc", true},
		{"ed25519 type errors via GenerateWithCharset", "ed25519", 256, "abc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := gen.GenerateWithCharset(tt.genType, tt.length, tt.charset)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result == "" {
				t.Error("expected non-empty result")
			}
		})
	}
}

func TestGenerateRSAKeypair(t *testing.T) {
	gen := NewSecretGenerator()

	tests := []struct {
		name      string
		bits      int
		wantError bool
	}{
		{"RSA 2048-bit", 2048, false},
		{"RSA 4096-bit", 4096, false},
		{"RSA 1024-bit minimum", 1024, false},
		{"RSA too small", 512, true},
		{"RSA zero bits", 0, true},
		{"RSA negative bits", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKeyPEM, publicKeyPEM, err := gen.GenerateRSAKeypair(tt.bits)

			if tt.wantError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, privateKeyPEM)
			assert.NotEmpty(t, publicKeyPEM)

			// Verify private key PEM format
			assert.True(t, strings.HasPrefix(privateKeyPEM, "-----BEGIN RSA PRIVATE KEY-----"))
			assert.True(t, strings.HasSuffix(strings.TrimSpace(privateKeyPEM), "-----END RSA PRIVATE KEY-----"))

			// Verify public key PEM format
			assert.True(t, strings.HasPrefix(publicKeyPEM, "-----BEGIN RSA PUBLIC KEY-----"))
			assert.True(t, strings.HasSuffix(strings.TrimSpace(publicKeyPEM), "-----END RSA PUBLIC KEY-----"))

			// Verify private key can be parsed
			block, _ := pem.Decode([]byte(privateKeyPEM))
			require.NotNil(t, block, "failed to decode private key PEM")
			privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			require.NoError(t, err)
			assert.Equal(t, tt.bits, privateKey.N.BitLen())

			// Verify public key can be parsed
			block, _ = pem.Decode([]byte(publicKeyPEM))
			require.NotNil(t, block, "failed to decode public key PEM")
			publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
			require.NoError(t, err)
			assert.Equal(t, tt.bits, publicKey.N.BitLen())
		})
	}
}

func TestGenerateRSAKeypairUniqueness(t *testing.T) {
	gen := NewSecretGenerator()
	priv1, _, err := gen.GenerateRSAKeypair(2048)
	require.NoError(t, err)
	priv2, _, err := gen.GenerateRSAKeypair(2048)
	require.NoError(t, err)
	assert.NotEqual(t, priv1, priv2, "two generated RSA keys should be different")
}

func TestGenerateECDSAKeypair(t *testing.T) {
	gen := NewSecretGenerator()

	tests := []struct {
		name      string
		curve     string
		wantCurve elliptic.Curve
		wantError bool
	}{
		{"P-256", "P-256", elliptic.P256(), false},
		{"P-384", "P-384", elliptic.P384(), false},
		{"P-521", "P-521", elliptic.P521(), false},
		{"invalid curve", "P-999", nil, true},
		{"empty curve", "", nil, true},
		{"lowercase curve", "p-256", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKeyPEM, publicKeyPEM, err := gen.GenerateECDSAKeypair(tt.curve)

			if tt.wantError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, privateKeyPEM)
			assert.NotEmpty(t, publicKeyPEM)

			// Verify private key PEM format
			assert.True(t, strings.HasPrefix(privateKeyPEM, "-----BEGIN EC PRIVATE KEY-----"))
			assert.True(t, strings.HasSuffix(strings.TrimSpace(privateKeyPEM), "-----END EC PRIVATE KEY-----"))

			// Verify public key PEM format
			assert.True(t, strings.HasPrefix(publicKeyPEM, "-----BEGIN PUBLIC KEY-----"))
			assert.True(t, strings.HasSuffix(strings.TrimSpace(publicKeyPEM), "-----END PUBLIC KEY-----"))

			// Verify private key can be parsed
			block, _ := pem.Decode([]byte(privateKeyPEM))
			require.NotNil(t, block, "failed to decode private key PEM")
			privateKey, err := x509.ParseECPrivateKey(block.Bytes)
			require.NoError(t, err)
			assert.Equal(t, tt.wantCurve, privateKey.Curve)

			// Verify public key can be parsed
			block, _ = pem.Decode([]byte(publicKeyPEM))
			require.NotNil(t, block, "failed to decode public key PEM")
			pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
			require.NoError(t, err)
			ecdsaPubKey, ok := pubKeyInterface.(*ecdsa.PublicKey)
			require.True(t, ok, "parsed public key is not ECDSA")
			assert.Equal(t, tt.wantCurve, ecdsaPubKey.Curve)
		})
	}
}

func TestGenerateECDSAKeypairUniqueness(t *testing.T) {
	gen := NewSecretGenerator()
	priv1, _, err := gen.GenerateECDSAKeypair("P-256")
	require.NoError(t, err)
	priv2, _, err := gen.GenerateECDSAKeypair("P-256")
	require.NoError(t, err)
	assert.NotEqual(t, priv1, priv2, "two generated ECDSA keys should be different")
}

func TestGenerateEd25519Keypair(t *testing.T) {
	gen := NewSecretGenerator()

	privateKeyPEM, publicKeyPEM, err := gen.GenerateEd25519Keypair()
	require.NoError(t, err)
	assert.NotEmpty(t, privateKeyPEM)
	assert.NotEmpty(t, publicKeyPEM)

	// Verify private key PEM format
	assert.True(t, strings.HasPrefix(privateKeyPEM, "-----BEGIN PRIVATE KEY-----"))
	assert.True(t, strings.HasSuffix(strings.TrimSpace(privateKeyPEM), "-----END PRIVATE KEY-----"))

	// Verify public key PEM format
	assert.True(t, strings.HasPrefix(publicKeyPEM, "-----BEGIN PUBLIC KEY-----"))
	assert.True(t, strings.HasSuffix(strings.TrimSpace(publicKeyPEM), "-----END PUBLIC KEY-----"))

	// Verify private key can be parsed
	block, _ := pem.Decode([]byte(privateKeyPEM))
	require.NotNil(t, block, "failed to decode private key PEM")
	privKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	_, ok := privKeyInterface.(ed25519.PrivateKey)
	require.True(t, ok, "parsed private key is not Ed25519")

	// Verify public key can be parsed
	block, _ = pem.Decode([]byte(publicKeyPEM))
	require.NotNil(t, block, "failed to decode public key PEM")
	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	_, ok = pubKeyInterface.(ed25519.PublicKey)
	require.True(t, ok, "parsed public key is not Ed25519")
}

func TestGenerateEd25519KeypairUniqueness(t *testing.T) {
	gen := NewSecretGenerator()
	priv1, _, err := gen.GenerateEd25519Keypair()
	require.NoError(t, err)
	priv2, _, err := gen.GenerateEd25519Keypair()
	require.NoError(t, err)
	assert.NotEqual(t, priv1, priv2, "two generated Ed25519 keys should be different")
}

func TestGenerateMLKEMKeypair(t *testing.T) {
	gen := NewSecretGenerator()

	tests := []struct {
		name           string
		param          string
		wantDKLen      int
		wantEKLen      int
		wantError      bool
		wantErrContain string
	}{
		{"ML-KEM-768", "768", 64, 1184, false, ""},
		{"ML-KEM-1024", "1024", 64, 1568, false, ""},
		{"invalid param", "512", 0, 0, true, "unsupported ML-KEM parameter"},
		{"empty param", "", 0, 0, true, "unsupported ML-KEM parameter"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dk, ek, err := gen.GenerateMLKEMKeypair(tt.param)

			if tt.wantError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrContain)
				return
			}

			require.NoError(t, err)
			assert.Len(t, dk, tt.wantDKLen, "decapsulation key length mismatch")
			assert.Len(t, ek, tt.wantEKLen, "encapsulation key length mismatch")
		})
	}
}

func TestGenerateMLKEMKeypairRoundtrip768(t *testing.T) {
	gen := NewSecretGenerator()

	dkBytes, ekBytes, err := gen.GenerateMLKEMKeypair("768")
	require.NoError(t, err)

	// Parse the encapsulation key and perform encapsulation
	ek, err := mlkem.NewEncapsulationKey768([]byte(ekBytes))
	require.NoError(t, err)

	sharedKey, ciphertext := ek.Encapsulate()

	// Parse the decapsulation key and perform decapsulation
	dk, err := mlkem.NewDecapsulationKey768([]byte(dkBytes))
	require.NoError(t, err)

	decapsulatedKey, err := dk.Decapsulate(ciphertext)
	require.NoError(t, err)

	assert.Equal(t, sharedKey, decapsulatedKey, "encapsulated and decapsulated shared keys must match")
}

func TestGenerateMLKEMKeypairRoundtrip1024(t *testing.T) {
	gen := NewSecretGenerator()

	dkBytes, ekBytes, err := gen.GenerateMLKEMKeypair("1024")
	require.NoError(t, err)

	// Parse the encapsulation key and perform encapsulation
	ek, err := mlkem.NewEncapsulationKey1024([]byte(ekBytes))
	require.NoError(t, err)

	sharedKey, ciphertext := ek.Encapsulate()

	// Parse the decapsulation key and perform decapsulation
	dk, err := mlkem.NewDecapsulationKey1024([]byte(dkBytes))
	require.NoError(t, err)

	decapsulatedKey, err := dk.Decapsulate(ciphertext)
	require.NoError(t, err)

	assert.Equal(t, sharedKey, decapsulatedKey, "encapsulated and decapsulated shared keys must match")
}

func TestGenerateMLKEMKeypairUniqueness(t *testing.T) {
	gen := NewSecretGenerator()
	dk1, _, err := gen.GenerateMLKEMKeypair("768")
	require.NoError(t, err)
	dk2, _, err := gen.GenerateMLKEMKeypair("768")
	require.NoError(t, err)
	assert.NotEqual(t, dk1, dk2, "two generated ML-KEM keys should be different")
}

func BenchmarkGenerateRSAKeypair2048(b *testing.B) {
	gen := NewSecretGenerator()
	for i := 0; i < b.N; i++ {
		_, _, _ = gen.GenerateRSAKeypair(2048)
	}
}

func BenchmarkGenerateECDSAKeypairP256(b *testing.B) {
	gen := NewSecretGenerator()
	for i := 0; i < b.N; i++ {
		_, _, _ = gen.GenerateECDSAKeypair("P-256")
	}
}

func BenchmarkGenerateEd25519Keypair(b *testing.B) {
	gen := NewSecretGenerator()
	for i := 0; i < b.N; i++ {
		_, _, _ = gen.GenerateEd25519Keypair()
	}
}

func BenchmarkGenerateMLKEMKeypair768(b *testing.B) {
	gen := NewSecretGenerator()
	for i := 0; i < b.N; i++ {
		_, _, _ = gen.GenerateMLKEMKeypair("768")
	}
}

func TestGenerateMLDSAKeypair(t *testing.T) {
	gen := NewSecretGenerator()

	tests := []struct {
		name           string
		param          string
		wantSKLen      int
		wantPKLen      int
		wantError      bool
		wantErrContain string
	}{
		{"ML-DSA-65", "65", 4032, 1952, false, ""},
		{"ML-DSA-87", "87", 4896, 2592, false, ""},
		{"invalid param", "44", 0, 0, true, "unsupported ML-DSA parameter"},
		{"empty param", "", 0, 0, true, "unsupported ML-DSA parameter"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sk, pk, err := gen.GenerateMLDSAKeypair(tt.param)

			if tt.wantError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrContain)
				return
			}

			require.NoError(t, err)
			assert.Len(t, sk, tt.wantSKLen, "private key length mismatch")
			assert.Len(t, pk, tt.wantPKLen, "public key length mismatch")
		})
	}
}

func TestGenerateMLDSAKeypairRoundtrip65(t *testing.T) {
	gen := NewSecretGenerator()

	skBytes, pkBytes, err := gen.GenerateMLDSAKeypair("65")
	require.NoError(t, err)

	// Unmarshal the private key
	var sk mldsa65.PrivateKey
	err = sk.UnmarshalBinary([]byte(skBytes))
	require.NoError(t, err)

	// Unmarshal the public key
	var pk mldsa65.PublicKey
	err = pk.UnmarshalBinary([]byte(pkBytes))
	require.NoError(t, err)

	// Sign a test message
	msg := []byte("test message for ML-DSA-65 roundtrip")
	sig, err := sk.Sign(rand.Reader, msg, nil)
	require.NoError(t, err)

	// Verify the signature
	valid := mldsa65.Verify(&pk, msg, nil, sig)
	assert.True(t, valid, "signature verification must succeed")
}

func TestGenerateMLDSAKeypairRoundtrip87(t *testing.T) {
	gen := NewSecretGenerator()

	skBytes, pkBytes, err := gen.GenerateMLDSAKeypair("87")
	require.NoError(t, err)

	// Unmarshal the private key
	var sk mldsa87.PrivateKey
	err = sk.UnmarshalBinary([]byte(skBytes))
	require.NoError(t, err)

	// Unmarshal the public key
	var pk mldsa87.PublicKey
	err = pk.UnmarshalBinary([]byte(pkBytes))
	require.NoError(t, err)

	// Sign a test message
	msg := []byte("test message for ML-DSA-87 roundtrip")
	sig, err := sk.Sign(rand.Reader, msg, nil)
	require.NoError(t, err)

	// Verify the signature
	valid := mldsa87.Verify(&pk, msg, nil, sig)
	assert.True(t, valid, "signature verification must succeed")
}

func TestGenerateMLDSAKeypairUniqueness(t *testing.T) {
	gen := NewSecretGenerator()
	sk1, _, err := gen.GenerateMLDSAKeypair("65")
	require.NoError(t, err)
	sk2, _, err := gen.GenerateMLDSAKeypair("65")
	require.NoError(t, err)
	assert.NotEqual(t, sk1, sk2, "two generated ML-DSA keys should be different")
}

func BenchmarkGenerateMLDSAKeypair65(b *testing.B) {
	gen := NewSecretGenerator()
	for i := 0; i < b.N; i++ {
		_, _, _ = gen.GenerateMLDSAKeypair("65")
	}
}

func TestGenerateSLHDSAKeypair(t *testing.T) {
	gen := NewSecretGenerator()

	tests := []struct {
		name           string
		param          string
		wantSKLen      int
		wantPKLen      int
		wantError      bool
		wantErrContain string
	}{
		{"SLH-DSA-SHA2-128s", "128s", 64, 32, false, ""},
		{"SLH-DSA-SHA2-128f", "128f", 64, 32, false, ""},
		{"SLH-DSA-SHA2-192s", "192s", 96, 48, false, ""},
		{"SLH-DSA-SHA2-192f", "192f", 96, 48, false, ""},
		{"SLH-DSA-SHA2-256s", "256s", 128, 64, false, ""},
		{"SLH-DSA-SHA2-256f", "256f", 128, 64, false, ""},
		{"invalid param", "999", 0, 0, true, "unsupported SLH-DSA parameter"},
		{"empty param", "", 0, 0, true, "unsupported SLH-DSA parameter"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sk, pk, err := gen.GenerateSLHDSAKeypair(tt.param)

			if tt.wantError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrContain)
				return
			}

			require.NoError(t, err)
			assert.Len(t, sk, tt.wantSKLen, "private key length mismatch")
			assert.Len(t, pk, tt.wantPKLen, "public key length mismatch")
		})
	}
}

func TestGenerateSLHDSAKeypairRoundtrip128s(t *testing.T) {
	gen := NewSecretGenerator()

	skBytes, pkBytes, err := gen.GenerateSLHDSAKeypair("128s")
	require.NoError(t, err)

	// Unmarshal the private key
	sk := slhdsa.PrivateKey{ID: slhdsa.SHA2_128s}
	err = sk.UnmarshalBinary([]byte(skBytes))
	require.NoError(t, err)

	// Unmarshal the public key
	pk := slhdsa.PublicKey{ID: slhdsa.SHA2_128s}
	err = pk.UnmarshalBinary([]byte(pkBytes))
	require.NoError(t, err)

	// Sign a test message
	msg := []byte("test message for SLH-DSA-128s roundtrip")
	sig, err := sk.Sign(rand.Reader, msg, nil)
	require.NoError(t, err)

	// Verify the signature
	valid := slhdsa.Verify(&pk, slhdsa.NewMessage(msg), sig, nil)
	assert.True(t, valid, "signature verification must succeed")
}

func TestGenerateSLHDSAKeypairRoundtrip256f(t *testing.T) {
	gen := NewSecretGenerator()

	skBytes, pkBytes, err := gen.GenerateSLHDSAKeypair("256f")
	require.NoError(t, err)

	// Unmarshal the private key
	sk := slhdsa.PrivateKey{ID: slhdsa.SHA2_256f}
	err = sk.UnmarshalBinary([]byte(skBytes))
	require.NoError(t, err)

	// Unmarshal the public key
	pk := slhdsa.PublicKey{ID: slhdsa.SHA2_256f}
	err = pk.UnmarshalBinary([]byte(pkBytes))
	require.NoError(t, err)

	// Sign a test message
	msg := []byte("test message for SLH-DSA-256f roundtrip")
	sig, err := sk.Sign(rand.Reader, msg, nil)
	require.NoError(t, err)

	// Verify the signature
	valid := slhdsa.Verify(&pk, slhdsa.NewMessage(msg), sig, nil)
	assert.True(t, valid, "signature verification must succeed")
}

func TestGenerateSLHDSAKeypairUniqueness(t *testing.T) {
	gen := NewSecretGenerator()
	sk1, _, err := gen.GenerateSLHDSAKeypair("128s")
	require.NoError(t, err)
	sk2, _, err := gen.GenerateSLHDSAKeypair("128s")
	require.NoError(t, err)
	assert.NotEqual(t, sk1, sk2, "two generated SLH-DSA keys should be different")
}

func BenchmarkGenerateSLHDSAKeypair128s(b *testing.B) {
	gen := NewSecretGenerator()
	for i := 0; i < b.N; i++ {
		_, _, _ = gen.GenerateSLHDSAKeypair("128s")
	}
}
