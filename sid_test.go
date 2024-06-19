package secureid

import (
	"strconv"
	"testing"
)

func TestIsSecureID_WithValidID_ReturnsTrue(t *testing.T) {
	id, _ := NewSID(10)
	if !IsSecureID(id, 10) {
		t.Errorf("Expected IsSecureID to return true for valid ID, got false")
	}
}

func TestIsSecureID_WithInvalidLength_ReturnsFalse(t *testing.T) {
	if IsSecureID("12345", 10) {
		t.Errorf("Expected IsSecureID to return false for ID of incorrect length, got true")
	}
}

func TestIsSecureID_WithInvalidCharacters_ReturnsFalse(t *testing.T) {
	if IsSecureID("abcdeabcde", 10) {
		t.Errorf("Expected IsSecureID to return false for ID with invalid characters, got true")
	}
}

func TestIsSecureID_WithEmptyString_ReturnsFalse(t *testing.T) {
	if IsSecureID("", 10) {
		t.Errorf("Expected IsSecureID to return false for empty string, got true")
	}
}

// BenchmarkGenerateSecureID benchmarks the generateSecureID function.
func BenchmarkGenerateSecureID(b *testing.B) {
	// Choose lengths to benchmark
	lengths := []int{7, 10, 15, 20}

	for _, length := range lengths {
		b.Run("Length"+strconv.Itoa(length), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := NewSID(length)
				if err != nil {
					b.Fatal("generateSecureID failed:", err)
				}
			}
		})
	}
}