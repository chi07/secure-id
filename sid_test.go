package secureid_test

import (
	"strconv"
	"testing"

	secureid "github.com/chi07/secure-id/v2"
)

func TestNewSID_Format(t *testing.T) {
	for _, length := range []int{9, 10, 12, 15, 20} {
		id, err := secureid.NewSID(length)
		if err != nil {
			t.Fatalf("NewSID(%d): %v", length, err)
		}
		if len(id) != length {
			t.Fatalf("NewSID(%d) produced %d chars", length, len(id))
		}
		if !secureid.IsSecureID(id, length) {
			t.Fatalf("IsSecureID rejected own output %q", id)
		}
	}
}

func TestNewSID_TooShort(t *testing.T) {
	for _, length := range []int{0, 1, 8, -3} {
		if _, err := secureid.NewSID(length); err == nil {
			t.Fatalf("NewSID(%d): expected error", length)
		}
	}
}

func TestNewSID_Unique(t *testing.T) {
	// Length 20 leaves 62^12 (~3.2e21) random values, so a collision in
	// 100k draws is astronomically unlikely — uniqueness at short lengths
	// is statistical by design, see NewSID docs.
	const n = 100_000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id, err := secureid.NewSID(20)
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate SID %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestIsSecureID(t *testing.T) {
	id, _ := secureid.NewSID(12)
	cases := []struct {
		id     string
		length int
		want   bool
	}{
		{id, 12, true},
		{id, 11, false},
		{"abcdeabcde", 10, true},   // charset-valid even if not a real SID
		{"abcde-abcde", 11, false}, // '-' not in base36
		{"abcdeabde!", 10, false},  // '!' not in base36
		{"", 10, false},
		{id, 0, false},
	}
	for _, c := range cases {
		if got := secureid.IsSecureID(c.id, c.length); got != c.want {
			t.Errorf("IsSecureID(%q, %d) = %v, want %v", c.id, c.length, got, c.want)
		}
	}
}

func TestNewSID_SortablePrefix(t *testing.T) {
	a, _ := secureid.NewSID(12)
	b, _ := secureid.NewSID(12)
	// Same millisecond → same prefix; otherwise later IDs sort after
	// earlier ones because the timestamp prefix is fixed-width base36.
	if a[:8] > b[:8] {
		t.Fatalf("timestamp prefix not sortable: %q vs %q", a, b)
	}
}

func BenchmarkNewSID(b *testing.B) {
	for _, length := range []int{9, 12, 16, 24} {
		b.Run("Len"+strconv.Itoa(length), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := secureid.NewSID(length); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkIsSecureID(b *testing.B) {
	id, _ := secureid.NewSID(12)
	b.ReportAllocs()
	for b.Loop() {
		_ = secureid.IsSecureID(id, 12)
	}
}
