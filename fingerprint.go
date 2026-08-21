package tamga

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// FingerprintComponent is one labelled input to CanonicalFingerprint —
// a name for what is being measured and the measured value.
//
// The label is part of the identity, not documentation: "disk=SN-9" and
// "board=SN-9" are different machines. Keep the labels an application uses
// stable across releases, because changing one changes the fingerprint and
// therefore consumes a new seat.
type FingerprintComponent struct {
	// Label names the component. Non-empty, ASCII printable (0x21-0x7E)
	// only, and may not contain '=' — the canonical form splits at the
	// first '=', so a label containing one would be ambiguous.
	Label string
	// Value is the measured value. Leading and trailing ASCII whitespace
	// is trimmed; the remainder may contain '=' and non-ASCII bytes, may
	// be empty, and may not contain any ASCII control character.
	Value string
}

// ErrInvalidFingerprintComponent is returned by CanonicalFingerprint for
// any input it refuses. Match it with errors.Is; the wrapped message names
// the offending label.
//
// Every refusal is an error rather than a silent repair, and that is the
// whole point of the helper. Stripping a control character or picking one
// of two values for a repeated label would map two different inputs onto
// one canonical string — which, given the server's uniqueness constraint,
// means two different machines onto one seat. That is the bug this exists
// to prevent, so it is never introduced while fixing a smaller one.
var ErrInvalidFingerprintComponent = errors.New("tamga: invalid fingerprint component")

// fingerprintDomain is the version-tagged domain separator that opens every
// canonical string, so a future v2 rule cannot produce a v1 fingerprint for
// a different input.
const fingerprintDomain = "tamga-fingerprint-v1"

// fingerprintSeparator is U+001F, the ASCII unit separator, emitted as the
// single byte 0x1f. It cannot appear inside a label (not ASCII printable)
// or inside a value (an ASCII control character), so the canonical string
// is unambiguously parseable back into its components.
const fingerprintSeparator = "\x1f"

// fingerprintTrimCutset is the ASCII whitespace trimmed from both ends of
// a value: space, tab, CR, LF, vertical tab, form feed.
//
// ⚠️ Deliberately NOT strings.TrimSpace, which trims Unicode whitespace —
// U+00A0, U+2000..U+200A and friends. Eight SDKs implement this rule, and
// "whatever this language calls whitespace" is exactly the kind of rule
// they would implement differently: a value ending in a non-breaking space
// would be trimmed by this SDK and kept by a port that trims only ASCII,
// yielding two fingerprints for one machine and silently double-billing.
// The set is enumerated here so it cannot drift.
const fingerprintTrimCutset = " \t\r\n\v\f"

// CanonicalFingerprint turns caller-chosen, labelled components into the
// stable machine fingerprint string to send as
// CreateMachineOptions.Fingerprint (and to Scope.Fingerprint, and to
// FindMachineByFingerprint).
//
// It is a pure function. It reads no hardware identifiers and never will:
// what identifies a machine is a product decision, not an SDK default. A
// cloned VM template shares its board and disk serials, a container has
// none of them, and a replaced motherboard changes them — no single choice
// is right for both a desktop application and a Kubernetes sidecar. Choose
// the components, then pass them here.
//
// # What this fixes
//
// The server stores `fingerprint TEXT NOT NULL` with no length limit, no
// CHECK and no normalisation, unique per (license_id, fingerprint). Sent
// raw — which is what every Tamga SDK did before this function existed —
// "ABC-123", "abc-123" and " ABC-123 " are three machines holding three
// seats against the same policy limit. Canonicalising first collapses the
// whitespace variants, orders the components so the caller's iteration
// order stops mattering, and rejects the inputs that would otherwise
// collide.
//
// # The algorithm
//
// Each component is trimmed and validated, rendered as label + "=" +
// trimmed value, and the resulting strings are sorted bytewise ascending.
// They are joined with U+001F, prefixed with "tamga-fingerprint-v1" and
// the same separator, and the UTF-8 bytes of that string are hashed with
// SHA-256. The result is the 64-character lowercase hex digest.
//
// Sorting is bytewise over the UTF-8 bytes of the whole "label=value"
// component — not locale-aware, and not code-point order over decoded
// characters.
//
// # Two rules that are absent on purpose
//
// Case is preserved. Lowercasing a base64 or hex identifier corrupts it,
// so "ABC123" and "abc123" are deliberately different machines.
//
// Values are NOT Unicode-normalised. NFC is unavailable without a new
// dependency in Go and in Rust, and in C11 it would mean ICU or hand-rolled
// Unicode tables inside a library whose selling point is having none. A rule
// eight ports cannot implement identically is worse than no rule: it would
// yield two fingerprints for one machine depending on which SDK the
// application was written in, silently consuming two seats. A caller whose
// values can arrive in more than one normal form must normalise them before
// calling.
//
// # Errors
//
// Returns an error wrapping ErrInvalidFingerprintComponent when no
// components are given, when a label is empty, non-ASCII-printable,
// contains '=' or is repeated, or when a value contains an ASCII control
// character after trimming. Nothing is silently repaired — see
// ErrInvalidFingerprintComponent.
//
//	fp, err := tamga.CanonicalFingerprint(
//		tamga.FingerprintComponent{Label: "machine-id", Value: machineID},
//		tamga.FingerprintComponent{Label: "disk", Value: diskSerial},
//	)
func CanonicalFingerprint(components ...FingerprintComponent) (string, error) {
	canonical, err := fingerprintCanonicalForm(components)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:]), nil
}

// fingerprintCanonicalForm builds the pre-hash canonical string. Kept
// separate so the test suite can assert the vectors' `canonical` field
// directly: a fingerprint test that only compares digests cannot say
// whether a mismatch came from the ordering, the trimming or the hash.
func fingerprintCanonicalForm(components []FingerprintComponent) (string, error) {
	if len(components) == 0 {
		return "", fmt.Errorf("%w: at least one component is required", ErrInvalidFingerprintComponent)
	}
	parts := make([]string, 0, len(components))
	seen := make(map[string]struct{}, len(components))
	for _, component := range components {
		if err := validateFingerprintLabel(component.Label); err != nil {
			return "", err
		}
		if _, duplicate := seen[component.Label]; duplicate {
			// Not deduplicated: two values for one label is a caller bug,
			// and picking one of them hides it behind a fingerprint that
			// depends on which one was picked.
			return "", fmt.Errorf("%w: label %q appears more than once", ErrInvalidFingerprintComponent, component.Label)
		}
		seen[component.Label] = struct{}{}
		value := strings.Trim(component.Value, fingerprintTrimCutset)
		if err := validateFingerprintValue(component.Label, value); err != nil {
			return "", err
		}
		parts = append(parts, component.Label+"="+value)
	}
	// Go compares strings bytewise, which is exactly the required order.
	slices.Sort(parts)
	return fingerprintDomain + fingerprintSeparator + strings.Join(parts, fingerprintSeparator), nil
}

// validateFingerprintLabel enforces the label rules: non-empty, ASCII
// printable 0x21-0x7E, no '='.
//
// Iterating bytes rather than runes is deliberate and sufficient: every
// byte of a multi-byte UTF-8 sequence is >= 0x80, so a non-ASCII label is
// caught by the same bound that catches a raw control byte. Labels are
// ASCII-only precisely so that they can never themselves need normalising.
func validateFingerprintLabel(label string) error {
	if label == "" {
		return fmt.Errorf("%w: a label must be non-empty", ErrInvalidFingerprintComponent)
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if c < 0x21 || c > 0x7E {
			return fmt.Errorf("%w: label %q contains byte %#02x; labels are ASCII printable 0x21-0x7e only", ErrInvalidFingerprintComponent, label, c)
		}
		if c == '=' {
			return fmt.Errorf("%w: label %q contains '=', which would make the split ambiguous", ErrInvalidFingerprintComponent, label)
		}
	}
	return nil
}

// validateFingerprintValue rejects any ASCII control character left after
// trimming. '=' and non-ASCII bytes are both legal here — the canonical
// form splits at the FIRST '=', so a value may contain as many as it likes.
func validateFingerprintValue(label, value string) error {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c <= 0x1F || c == 0x7F {
			return fmt.Errorf("%w: value for label %q contains control byte %#02x; control characters are rejected, never stripped", ErrInvalidFingerprintComponent, label, c)
		}
	}
	return nil
}
