package tamga

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	internalcrypto "github.com/tamga-sh/tamga-go/internal/crypto"
)

// ProofPrefix prefixes every offline proof string this SDK generates or
// verifies: "v1x0.<base64 signature>".
const ProofPrefix = "v1x0."

// GenerateOfflineProof requests a lightweight, air-gapped-friendly
// alternative to full machine checkout (CheckOutMachine): "prove this
// machine is still valid" without downloading a full offline file.
// POST /v1/accounts/{account_id}/machines/{id}/actions/generate-offline-proof.
//
// dataset, if nil, defaults to {} in the request body — the server
// requires a JSON object (not an array/scalar), failing with an error
// matching ErrDatasetInvalid otherwise.
//
// Always signed with RSA-2048 PKCS#1 v1.5 / SHA-256, regardless of the
// license's own Scheme — unlike machine checkout (CheckOutMachine), this
// is never scheme-driven. Returns the updated machine resource plus the
// "v1x0.<base64>" proof string; pass the proof, plus the exact
// (accountID, machineID, fingerprint, dataset) tuple used here, to
// VerifyOfflineProof to verify it fully offline.
//
// ⚠️ Known limitation (found in security review, documented rather than
// fully closed): dataset's JSON serialization must byte-exactly match the
// server's Rust serde_json output for VerifyOfflineProof to succeed (see
// buildOfflineProofPayloadJSON's doc comment). This SDK's serdeCompatMarshal
// closes the HTML-escaping and U+2028/U+2029 gaps between Go's
// encoding/json and serde_json, but does NOT guarantee identical float
// formatting at extreme magnitudes — Go's float64 formatter and Rust's
// ryu-based one can choose different decimal-vs-scientific-notation
// cutoffs for very large/small values (e.g. 1e20). Prefer integer
// (int/int64), string, and small/typical float64 dataset values — the
// kind of telemetry (core counts, memory sizes, timestamps) this endpoint
// is actually intended for — to stay well inside the range where the two
// formatters agree.
func (c *Client) GenerateOfflineProof(ctx context.Context, machineID string, dataset map[string]any) (*Machine, string, error) {
	if dataset == nil {
		dataset = map[string]any{}
	}
	body := map[string]any{"meta": map[string]any{"dataset": dataset}}
	path := fmt.Sprintf("/machines/%s/actions/generate-offline-proof", escapePathSegment(machineID))

	type proofMeta struct {
		Proof string `json:"proof"`
	}
	machine, meta, err := decodeJSONAPIWithMeta[Machine, proofMeta](ctx, c, "POST", path, body)
	if err != nil {
		return nil, "", err
	}
	return &machine, meta.Proof, nil
}

// ParseProof splits a "v1x0.<base64 signature>" proof string into its
// raw signature bytes.
func ParseProof(proof string) ([]byte, error) {
	sigB64, ok := strings.CutPrefix(proof, ProofPrefix)
	if !ok {
		return nil, fmt.Errorf("tamga: malformed proof: missing %q prefix", ProofPrefix)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("tamga: invalid base64 in proof signature: %w", err)
	}
	return sig, nil
}

// buildOfflineProofPayloadJSON builds the byte-exact JSON payload the
// server signs.
//
// ⚠️ THE CENTRAL GOTCHA OF THIS FILE: the server builds this payload via
// Rust's serde_json::json!({"account": ..., "machine": ..., "dataset":
// ...}) macro — but serde_json::Map is BTreeMap-backed (alphabetically
// sorted output) in tamga-api's dependency graph (confirmed: no `indexmap`
// paired with `serde_json` to enable the `preserve_order` feature — see
// tamga-rust's CLAUDE.md and its proof.rs module doc comment, the
// ground-truth analysis this Go port relies on). So despite the server's
// source code being written in "account, machine, dataset" order, the
// actual bytes on the wire are alphabetically sorted at EVERY nesting
// level: {"account":{"id":...},"dataset":...,"machine":{"fingerprint":...,
// "id":...}} — "dataset" before "machine", and "fingerprint" before "id"
// inside machine, neither of which matches the server's literal source
// order.
//
// A fixed-field-order Go struct declared in the server's literal source
// order would therefore be WRONG here — it would produce
// {"account":...,"machine":...,"dataset":...}, which does not match the
// wire bytes. The correct approach (used here, mirroring tamga-rust's own
// serde_json::Value-based fix) is building the payload from nested
// map[string]any and letting encoding/json's own key-sorting do the work:
// Go's encoding/json unconditionally sorts map[string]T keys alphabetically
// when marshaling (this is a documented stdlib guarantee, not
// version-dependent behavior like Rust's serde_json — verified directly:
// json.Marshal(map[string]any{"b":1,"a":2}) always produces {"a":1,"b":2}).
// This is MORE robust than a hand-ordered struct, not less: it doesn't
// depend on whoever writes this SDK correctly guessing and hardcoding the
// server's sort order, and self-normalizes to the same canonical order the
// server produces regardless of the literal construction order below. The
// one real requirement still holds: never use a non-deterministic-
// iteration-order type here — map[string]any's deterministic (sorted, on
// marshal) behavior is exactly what's needed, not what to avoid.
//
// ⚠️ A SECOND, SEPARATE BYTE-EXACTNESS GOTCHA (found in security review):
// plain json.Marshal is NOT enough on its own. Go's encoding/json (a) HTML-
// escapes '<', '>', and '&' to "<"/">"/"&" by default, and
// (b) unconditionally escapes U+2028/U+2029 (LINE SEPARATOR/PARAGRAPH
// SEPARATOR) regardless of that setting — neither of which
// tamga-api's pinned serde_json version does by default. A dataset value
// containing any of those five characters (a URL query string, a pasted
// line of rich text, an email display name, ...) would otherwise produce
// different signed bytes client-side than the server actually signed,
// causing VerifyOfflineProof to reject a genuinely valid, server-issued
// proof. serdeCompatMarshal (below) disables HTML-escaping and reverses
// the unconditional U+2028/U+2029 escaping via a byte-level, escape-
// sequence-aware scanner (never a blind string search-and-replace, which
// would misfire on a user string that literally contains the six ASCII
// characters backslash/u/2/0/2/8 as ordinary data rather than as an
// encoder-emitted escape -- see that function's own doc comment and
// proof_test.go's regression tests covering exactly this).
func buildOfflineProofPayloadJSON(accountID, machineID, fingerprint string, dataset map[string]any) ([]byte, error) {
	if dataset == nil {
		dataset = map[string]any{}
	}
	payload := map[string]any{
		"account": map[string]any{"id": accountID},
		"machine": map[string]any{"id": machineID, "fingerprint": fingerprint},
		"dataset": dataset,
	}
	return serdeCompatMarshal(payload)
}

// u2028Escape/u2029Escape are the literal 6-byte ASCII escape sequences
// (backslash, 'u', '2', '0', '2', '8'/'9') encoding/json emits for
// U+2028/U+2029. Built from byte literals, not a string containing the
// literal backslash-u text, so there is no ambiguity about their exact
// byte content.
var (
	u2028Escape = []byte{'\\', 'u', '2', '0', '2', '8'}
	u2029Escape = []byte{'\\', 'u', '2', '0', '2', '9'}
	u2028Rune   = []byte(string(rune(0x2028)))
	u2029Rune   = []byte(string(rune(0x2029)))
)

// serdeCompatMarshal marshals v to JSON matching Rust serde_json's default
// output byte-for-byte for the character classes that differ between the
// two (see buildOfflineProofPayloadJSON's doc comment for why this
// matters): HTML-escaping is disabled, and U+2028/U+2029 are left as raw
// UTF-8 instead of encoding/json's unconditional \u-escaping. Map key
// sorting (the section's other, already-covered gotcha) is unaffected —
// both json.Marshal and json.Encoder.Encode sort map[string]T keys
// alphabetically the same way.
func serdeCompatMarshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encoder.Encode appends a trailing newline Marshal doesn't produce.
	out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	return unescapeLineAndParagraphSeparators(out), nil
}

// unescapeLineAndParagraphSeparators reverses encoding/json's unconditional
// U+2028/U+2029 escaping, restoring the raw UTF-8 bytes to match
// serde_json's default (unescaped) output — but only for genuine
// single-backslash escape sequences the encoder itself produced, never for
// a literal occurrence of that 6-byte ASCII text inside already-escaped
// user data. A user string containing a literal backslash followed by the
// text "u2028" gets encoded as "\\u2028" (an escaped-backslash token
// followed by plain text) — a blind substring replace would incorrectly
// match the second half of that as if it were a real U+2028 escape and
// corrupt the output. This function instead scans byte-by-byte and
// consumes every escape token atomically (2 bytes for \\, \", \/, \b, \f,
// \n, \r, \t; 6 bytes for any \uXXXX), so it can never misinterpret a
// literal escaped-backslash-plus-text sequence as a unicode escape.
func unescapeLineAndParagraphSeparators(in []byte) []byte {
	out := make([]byte, 0, len(in))
	i := 0
	for i < len(in) {
		if in[i] == '\\' && i+1 < len(in) {
			switch in[i+1] {
			case 'u':
				if i+6 <= len(in) {
					switch {
					case bytes.Equal(in[i:i+6], u2028Escape):
						out = append(out, u2028Rune...)
					case bytes.Equal(in[i:i+6], u2029Escape):
						out = append(out, u2029Rune...)
					default:
						out = append(out, in[i:i+6]...)
					}
					i += 6
					continue
				}
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				out = append(out, in[i], in[i+1])
				i += 2
				continue
			}
		}
		out = append(out, in[i])
		i++
	}
	return out
}

// VerifyOfflineProof verifies a "v1x0.<base64 signature>" offline proof
// (from GenerateOfflineProof's returned proof string) against the exact
// (accountID, machineID, fingerprint, dataset) tuple it should have been
// generated for. Always RSA-2048 PKCS#1 v1.5 / SHA-256, regardless of the
// license's own Scheme. Works fully offline once pub (the account's RSA
// public key) is embedded in the calling application.
//
// Reuses internal/crypto/rsa.go's VerifyRSAPKCS1v15 — the same
// implementation checkout_machine.go's RSA_2048_PKCS1_SIGN path uses, not
// a second copy.
func VerifyOfflineProof(pub *rsa.PublicKey, accountID, machineID, fingerprint string, dataset map[string]any, proof string) error {
	if pub == nil {
		return fmt.Errorf("tamga: VerifyOfflineProof: pub must not be nil")
	}
	sig, err := ParseProof(proof)
	if err != nil {
		return err
	}
	payloadJSON, err := buildOfflineProofPayloadJSON(accountID, machineID, fingerprint, dataset)
	if err != nil {
		return fmt.Errorf("tamga: build offline proof payload: %w", err)
	}
	if err := internalcrypto.VerifyRSAPKCS1v15(pub, payloadJSON, sig); err != nil {
		return ErrInvalidSignature
	}
	return nil
}
