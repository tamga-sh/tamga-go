package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestDeriveLicenseFileKey_ZeroPadTruncateBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		keyLen  int
		wantLen int // always 32; documents intent per case
	}{
		{"zero_bytes", 0, 32},
		{"one_byte", 1, 32},
		{"thirty_one_bytes", 31, 32},
		{"exactly_thirty_two_bytes", 32, 32},
		{"thirty_three_bytes", 33, 32},
		{"one_hundred_bytes", 100, 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := strings.Repeat("k", tt.keyLen)
			got := DeriveLicenseFileKey(input)
			if len(got) != tt.wantLen {
				t.Fatalf("len(DeriveLicenseFileKey(...)) = %d, want %d", len(got), tt.wantLen)
			}
			// Every non-zero-padded byte must be 'k' (0x6b); every byte
			// beyond min(keyLen, 32) must be the zero pad.
			for i := 0; i < 32; i++ {
				if i < tt.keyLen && i < 32 {
					if got[i] != 'k' {
						t.Fatalf("byte %d = %x, want 'k' (copied from input)", i, got[i])
					}
				} else {
					if got[i] != 0 {
						t.Fatalf("byte %d = %x, want 0x00 (zero pad)", i, got[i])
					}
				}
			}
		})
	}
}

func TestDeriveLicenseFileKey_ExactBoundaryContent(t *testing.T) {
	got := DeriveLicenseFileKey("short")
	if string(got[:5]) != "short" {
		t.Fatalf("got[:5] = %q, want \"short\"", got[:5])
	}
	for i := 5; i < 32; i++ {
		if got[i] != 0 {
			t.Fatalf("got[%d] = %x, want 0x00", i, got[i])
		}
	}
}

func TestDeriveLicenseFileKey_TruncatesKeysLongerThan32Bytes(t *testing.T) {
	long := strings.Repeat("a", 50)
	got := DeriveLicenseFileKey(long)
	want := [32]byte{}
	for i := range want {
		want[i] = 'a'
	}
	if got != want {
		t.Fatalf("got = %x, want 32 bytes of 'a'", got)
	}
}

// TestDeriveLicenseFileKey_IsNotAHash proves this transform is a literal
// byte-copy, not a hash/KDF: two inputs sharing a prefix must produce
// derived keys sharing that same prefix. A real KDF would produce
// completely unrelated output for any input change — this is the
// documented, intentional non-KDF behavior (see naivekey.go's doc
// comment), not a bug this test would be catching.
func TestDeriveLicenseFileKey_IsNotAHash(t *testing.T) {
	a := DeriveLicenseFileKey("abc")
	b := DeriveLicenseFileKey("abcdef")
	if !bytes.Equal(a[:3], b[:3]) {
		t.Fatalf("a[:3] = %x, b[:3] = %x, want equal prefixes (proves this is not hashing)", a[:3], b[:3])
	}
}
