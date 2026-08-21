package tamga

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// fingerprintVectorFile mirrors testdata/fingerprint-vectors.json, the
// cross-SDK vector set. It was produced by an independent SHA-256
// implementation, not by any SDK — a fixture an SDK generated can only
// prove that SDK agrees with itself, which is precisely the failure mode
// eight independently-written canonicalisers would exhibit.
type fingerprintVectorFile struct {
	// Field order here is chosen for govet's fieldalignment, not for
	// readability: the slices sort last so the struct's pointer-bearing
	// prefix is as short as possible. Decoding does not care.
	Vectors []struct {
		Name        string      `json:"name"`
		Canonical   string      `json:"canonical"`
		Fingerprint string      `json:"fingerprint"`
		Note        string      `json:"note"`
		Components  [][2]string `json:"components"`
	} `json:"vectors"`
	Rejected []struct {
		Name       string      `json:"name"`
		Reason     string      `json:"reason"`
		Components [][2]string `json:"components"`
	} `json:"rejected"`
}

func loadFingerprintVectors(t *testing.T) fingerprintVectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/fingerprint-vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var file fingerprintVectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	if len(file.Vectors) == 0 || len(file.Rejected) == 0 {
		t.Fatalf("vector file is empty: %d positive, %d rejected", len(file.Vectors), len(file.Rejected))
	}
	return file
}

func fingerprintComponentsFrom(pairs [][2]string) []FingerprintComponent {
	components := make([]FingerprintComponent, 0, len(pairs))
	for _, pair := range pairs {
		components = append(components, FingerprintComponent{Label: pair[0], Value: pair[1]})
	}
	return components
}

// expandUS turns the vector file's display placeholder into the byte the
// canonical form actually carries. The file writes "<US>" so the canonical
// strings stay readable in a diff; the hash is over the real 0x1f.
func expandUS(s string) string {
	return strings.ReplaceAll(s, "<US>", "\x1f")
}

func TestCanonicalFingerprint_Vectors(t *testing.T) {
	file := loadFingerprintVectors(t)
	for _, vector := range file.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			components := fingerprintComponentsFrom(vector.Components)

			canonical, err := fingerprintCanonicalForm(components)
			if err != nil {
				t.Fatalf("fingerprintCanonicalForm() error = %v", err)
			}
			// Asserting the canonical form separately is what makes a
			// failure diagnosable: a digest mismatch alone cannot say
			// whether the ordering, the trimming or the hash is wrong.
			if want := expandUS(vector.Canonical); canonical != want {
				t.Errorf("canonical = %q, want %q (%s)", canonical, want, vector.Note)
			}

			got, err := CanonicalFingerprint(components...)
			if err != nil {
				t.Fatalf("CanonicalFingerprint() error = %v", err)
			}
			if got != vector.Fingerprint {
				t.Errorf("fingerprint = %s, want %s (%s)", got, vector.Fingerprint, vector.Note)
			}
			if len(got) != 64 {
				t.Errorf("fingerprint length = %d, want 64 lowercase hex chars", len(got))
			}
			if got != strings.ToLower(got) {
				t.Errorf("fingerprint = %s, want lowercase hex", got)
			}
		})
	}
}

func TestCanonicalFingerprint_RejectedVectors(t *testing.T) {
	file := loadFingerprintVectors(t)
	for _, vector := range file.Rejected {
		t.Run(vector.Name, func(t *testing.T) {
			components := fingerprintComponentsFrom(vector.Components)
			got, err := CanonicalFingerprint(components...)
			if err == nil {
				t.Fatalf("CanonicalFingerprint() = %s, want an error (%s)", got, vector.Reason)
			}
			// Rejection must be an error, never a silently repaired
			// value: stripping a control character or deduplicating a
			// repeated label maps two different inputs onto one canonical
			// string, and therefore two machines onto one seat.
			if got != "" {
				t.Errorf("CanonicalFingerprint() = %q on the error path, want the empty string", got)
			}
			if !errors.Is(err, ErrInvalidFingerprintComponent) {
				t.Errorf("error = %v, want it to wrap ErrInvalidFingerprintComponent", err)
			}
		})
	}
}

// vectorFingerprint looks a named positive vector's expected digest up, so
// the invariant tests below assert against the file rather than against
// whatever this implementation happens to produce.
func vectorFingerprint(t *testing.T, file fingerprintVectorFile, name string) string {
	t.Helper()
	for _, vector := range file.Vectors {
		if vector.Name == name {
			return vector.Fingerprint
		}
	}
	t.Fatalf("vector %q is missing from the file", name)
	return ""
}

// TestCanonicalFingerprint_OrderIndependence pins the first of the three
// invariants the vector file gives a pair for. Component order is the
// caller's convenience — iterating a map, appending in discovery order —
// and must not be part of the identity, or the same machine consumes a new
// seat whenever the caller's iteration order changes.
func TestCanonicalFingerprint_OrderIndependence(t *testing.T) {
	file := loadFingerprintVectors(t)
	sorted := vectorFingerprint(t, file, "two_sorted")
	unsorted := vectorFingerprint(t, file, "two_unsorted")
	if sorted != unsorted {
		t.Fatalf("the vector file itself disagrees: two_sorted %s != two_unsorted %s", sorted, unsorted)
	}

	a, err := CanonicalFingerprint(
		FingerprintComponent{Label: "disk", Value: "SN-9"},
		FingerprintComponent{Label: "machine-id", Value: "abc123"},
	)
	if err != nil {
		t.Fatalf("CanonicalFingerprint() error = %v", err)
	}
	b, err := CanonicalFingerprint(
		FingerprintComponent{Label: "machine-id", Value: "abc123"},
		FingerprintComponent{Label: "disk", Value: "SN-9"},
	)
	if err != nil {
		t.Fatalf("CanonicalFingerprint() error = %v", err)
	}
	if a != b {
		t.Errorf("caller order changed the fingerprint: %s != %s", a, b)
	}
	if a != sorted {
		t.Errorf("fingerprint = %s, want the vector's %s", a, sorted)
	}
}

// TestCanonicalFingerprint_WhitespaceEquivalence pins the second invariant.
// " ABC-123 " and "ABC-123" were two seats before this function existed:
// the server stores the string verbatim and its uniqueness constraint is
// over the raw bytes.
func TestCanonicalFingerprint_WhitespaceEquivalence(t *testing.T) {
	file := loadFingerprintVectors(t)
	want := vectorFingerprint(t, file, "single")
	if trimmed := vectorFingerprint(t, file, "whitespace_trimmed"); trimmed != want {
		t.Fatalf("the vector file itself disagrees: whitespace_trimmed %s != single %s", trimmed, want)
	}

	for _, value := range []string{"abc123", " abc123", "abc123 ", "  abc123\t\n", "\r\n\vabc123\f "} {
		got, err := CanonicalFingerprint(FingerprintComponent{Label: "machine-id", Value: value})
		if err != nil {
			t.Fatalf("CanonicalFingerprint(%q) error = %v", value, err)
		}
		if got != want {
			t.Errorf("CanonicalFingerprint(%q) = %s, want %s", value, got, want)
		}
	}
}

// TestCanonicalFingerprint_CasePreserved pins the third invariant, which is
// the one that is an absence rather than a transformation: case folding is
// deliberately NOT applied, because lowercasing a base64 or hex identifier
// corrupts it.
func TestCanonicalFingerprint_CasePreserved(t *testing.T) {
	file := loadFingerprintVectors(t)
	lower := vectorFingerprint(t, file, "single")
	upper := vectorFingerprint(t, file, "case_preserved")
	if lower == upper {
		t.Fatalf("the vector file itself disagrees: case_preserved equals single (%s)", lower)
	}

	got, err := CanonicalFingerprint(FingerprintComponent{Label: "machine-id", Value: "ABC123"})
	if err != nil {
		t.Fatalf("CanonicalFingerprint() error = %v", err)
	}
	if got != upper {
		t.Errorf("fingerprint = %s, want %s", got, upper)
	}
	if got == lower {
		t.Errorf("case was folded: %q and %q produced the same fingerprint", "ABC123", "abc123")
	}

	// Labels are case-sensitive for the same reason, and that also means
	// two labels differing only in case are NOT duplicates.
	mixed, err := CanonicalFingerprint(
		FingerprintComponent{Label: "id", Value: "a"},
		FingerprintComponent{Label: "ID", Value: "b"},
	)
	if err != nil {
		t.Fatalf("CanonicalFingerprint() error = %v", err)
	}
	if mixed == "" {
		t.Error("expected a fingerprint for two labels differing only in case")
	}
}

// TestCanonicalFingerprint_TrimsASCIIWhitespaceOnly guards the divergence
// the vector file cannot: strings.TrimSpace trims Unicode whitespace, and a
// port that reached for its language's "trim whitespace" default would trim
// U+00A0 while a port that enumerated the ASCII set would not — two
// fingerprints for one machine, silently double-billing. The spec's trim set
// is ASCII only, so a non-breaking space is part of the value.
func TestCanonicalFingerprint_TrimsASCIIWhitespaceOnly(t *testing.T) {
	file := loadFingerprintVectors(t)
	plain := vectorFingerprint(t, file, "single")

	nbsp, err := CanonicalFingerprint(FingerprintComponent{Label: "machine-id", Value: " abc123 "})
	if err != nil {
		t.Fatalf("CanonicalFingerprint() error = %v", err)
	}
	if nbsp == plain {
		t.Error("U+00A0 was trimmed; the trim set is ASCII whitespace only")
	}

	canonical, err := fingerprintCanonicalForm([]FingerprintComponent{{Label: "machine-id", Value: " abc123 "}})
	if err != nil {
		t.Fatalf("fingerprintCanonicalForm() error = %v", err)
	}
	if !strings.Contains(canonical, "machine-id= abc123 ") {
		t.Errorf("canonical = %q, want the non-breaking spaces preserved", canonical)
	}
}

// TestCanonicalFingerprint_SortIsBytewiseOverTheWholeComponent pins the
// ordering rule at the two places a plausible alternative reading diverges.
//
// Sorting decoded code points is NOT one of them, despite being the reading
// the spec explicitly rules out: UTF-8 byte order and code-point order are
// mathematically identical, so in Go the two implementations cannot be told
// apart. (The reading that genuinely differs is UTF-16 code-unit order,
// which a JavaScript port would get from a bare Array.sort — and labels are
// ASCII-only and unique, so they alone decide the order and no value ever
// reaches the comparison. The rule is stated for the ports where it bites.)
//
// What does diverge in Go is below.
func TestCanonicalFingerprint_SortIsBytewiseOverTheWholeComponent(t *testing.T) {
	// 1. The sort key is the whole "label=value" string, not the label.
	//    'a' sorts before 'a-b' when only labels are compared, because the
	//    shorter string wins on a prefix; comparing the rendered components
	//    puts '-' (0x2d) against '=' (0x3d) and reverses them.
	canonical, err := fingerprintCanonicalForm([]FingerprintComponent{
		{Label: "a", Value: "x"},
		{Label: "a-b", Value: "y"},
	})
	if err != nil {
		t.Fatalf("fingerprintCanonicalForm() error = %v", err)
	}
	if want := "tamga-fingerprint-v1\x1fa-b=y\x1fa=x"; canonical != want {
		t.Errorf("canonical = %q, want %q — the sort key is the rendered component, not the label", canonical, want)
	}

	// 2. The comparison is case-sensitive, like every other rule here.
	//    Bytewise puts every uppercase ASCII letter below every lowercase
	//    one; a case-insensitive sort would swap these.
	canonical, err = fingerprintCanonicalForm([]FingerprintComponent{
		{Label: "a", Value: "2"},
		{Label: "B", Value: "1"},
	})
	if err != nil {
		t.Fatalf("fingerprintCanonicalForm() error = %v", err)
	}
	if want := "tamga-fingerprint-v1\x1fB=1\x1fa=2"; canonical != want {
		t.Errorf("canonical = %q, want %q — the sort is bytewise, not case-insensitive", canonical, want)
	}
}

// TestCanonicalFingerprint_DomainSeparatorAndSeparatorByte asserts the two
// literals a port is most likely to paraphrase: the version-tagged prefix
// that keeps a future v2 rule from colliding with v1, and the separator
// being the single byte 0x1f rather than the four characters "<US>" the
// vector file displays.
func TestCanonicalFingerprint_DomainSeparatorAndSeparatorByte(t *testing.T) {
	canonical, err := fingerprintCanonicalForm([]FingerprintComponent{{Label: "machine-id", Value: "abc123"}})
	if err != nil {
		t.Fatalf("fingerprintCanonicalForm() error = %v", err)
	}
	if !strings.HasPrefix(canonical, "tamga-fingerprint-v1\x1f") {
		t.Errorf("canonical = %q, want the tamga-fingerprint-v1 domain prefix followed by 0x1f", canonical)
	}
	if strings.Contains(canonical, "<US>") {
		t.Error("the literal <US> placeholder leaked into the canonical string; it must be the byte 0x1f")
	}
	if strings.Count(canonical, "\x1f") != 1 {
		t.Errorf("canonical = %q, want exactly one separator for one component", canonical)
	}
}

// TestCanonicalFingerprint_RejectionMessagesNameTheLabel keeps the errors
// actionable: a caller assembling components in a loop needs to know which
// one was refused.
func TestCanonicalFingerprint_RejectionMessagesNameTheLabel(t *testing.T) {
	tests := []struct {
		name       string
		wantIn     string
		components []FingerprintComponent
	}{
		{
			name:       "duplicate label",
			components: []FingerprintComponent{{Label: "id", Value: "a"}, {Label: "id", Value: "b"}},
			wantIn:     `"id"`,
		},
		{
			name:       "control character in value",
			components: []FingerprintComponent{{Label: "disk", Value: "a\x07b"}},
			wantIn:     `"disk"`,
		},
		{
			name:       "equals in label",
			components: []FingerprintComponent{{Label: "a=b", Value: "x"}},
			wantIn:     `"a=b"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CanonicalFingerprint(tt.components...)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.wantIn) {
				t.Errorf("error = %q, want it to mention %s", err.Error(), tt.wantIn)
			}
		})
	}
}

// TestCanonicalFingerprint_DeleteAndTabAreRejectedAfterTrimming covers the
// two control-character boundaries the vector file does not spell out: DEL
// (0x7F) is not below 0x20 and so needs its own check, and an interior tab
// is a control character even though a leading or trailing one is trimmed.
func TestCanonicalFingerprint_DeleteAndTabAreRejectedAfterTrimming(t *testing.T) {
	for _, value := range []string{"a\x7fb", "a\tb", "a\x00b", "a\x1fb"} {
		if _, err := CanonicalFingerprint(FingerprintComponent{Label: "id", Value: value}); err == nil {
			t.Errorf("CanonicalFingerprint(%q) = no error, want a rejection", value)
		} else if !errors.Is(err, ErrInvalidFingerprintComponent) {
			t.Errorf("CanonicalFingerprint(%q) error = %v, want ErrInvalidFingerprintComponent", value, err)
		}
	}
	// A value that is nothing but trimmable whitespace becomes the empty
	// value, which is legal — the label still contributes.
	got, err := CanonicalFingerprint(FingerprintComponent{Label: "id", Value: " \t\n "})
	if err != nil {
		t.Fatalf("CanonicalFingerprint() error = %v", err)
	}
	empty, err := CanonicalFingerprint(FingerprintComponent{Label: "id", Value: ""})
	if err != nil {
		t.Fatalf("CanonicalFingerprint() error = %v", err)
	}
	if got != empty {
		t.Errorf("an all-whitespace value %s did not trim to the empty value %s", got, empty)
	}
}
