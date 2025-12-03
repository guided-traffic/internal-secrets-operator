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
	"strings"
	"testing"
)

func TestNewSecretGenerator(t *testing.T) {
	gen := NewSecretGenerator()
	if gen == nil {
		t.Fatal("NewSecretGenerator returned nil")
	}
	if gen.defaultCharset != AlphanumericCharset {
		t.Errorf("expected charset %q, got %q", AlphanumericCharset, gen.defaultCharset)
	}
}

func TestNewSecretGeneratorWithCharset(t *testing.T) {
	customCharset := "abc123"
	gen := NewSecretGeneratorWithCharset(customCharset)
	if gen == nil {
		t.Fatal("NewSecretGeneratorWithCharset returned nil")
	}
	if gen.defaultCharset != customCharset {
		t.Errorf("expected charset %q, got %q", customCharset, gen.defaultCharset)
	}
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
