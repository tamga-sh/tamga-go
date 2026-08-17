package tamga

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"
)

func TestGenerateOfflineProof_RequestResponseRoundTrip(t *testing.T) {
	var gotBody map[string]any
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + representativeMachineJSON + `,"meta":{"proof":"v1x0.c2lnbmF0dXJl"}}`))
	})
	defer closeFn()

	machine, proof, err := c.GenerateOfflineProof(context.Background(), "mach-id", map[string]any{"cores": 4})
	if err != nil {
		t.Fatalf("GenerateOfflineProof() error = %v", err)
	}
	if machine.Attributes.Fingerprint != "fp-abc123" {
		t.Errorf("Fingerprint = %q", machine.Attributes.Fingerprint)
	}
	if proof != "v1x0.c2lnbmF0dXJl" {
		t.Errorf("proof = %q", proof)
	}
	meta := gotBody["meta"].(map[string]any)
	dataset := meta["dataset"].(map[string]any)
	if dataset["cores"].(float64) != 4 {
		t.Errorf("dataset = %+v", dataset)
	}
}

func TestGenerateOfflineProof_NilDatasetDefaultsToEmptyObject(t *testing.T) {
	var gotBody map[string]any
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + representativeMachineJSON + `,"meta":{"proof":"v1x0.c2lnbmF0dXJl"}}`))
	})
	defer closeFn()

	_, _, err := c.GenerateOfflineProof(context.Background(), "mach-id", nil)
	if err != nil {
		t.Fatalf("GenerateOfflineProof() error = %v", err)
	}
	meta := gotBody["meta"].(map[string]any)
	dataset, ok := meta["dataset"].(map[string]any)
	if !ok || len(dataset) != 0 {
		t.Errorf("dataset = %+v, want empty object", meta["dataset"])
	}
}

func TestGenerateOfflineProof_DatasetInvalidMapping(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"errors":[{"id":"e1","status":"422","code":"DATASET_INVALID","title":"Unprocessable Entity","detail":"dataset must be an object"}]}`))
	})
	defer closeFn()

	_, _, err := c.GenerateOfflineProof(context.Background(), "mach-id", map[string]any{"cores": 4})
	if !errors.Is(err, ErrDatasetInvalid) {
		t.Fatalf("errors.Is(err, ErrDatasetInvalid) = false, err = %v", err)
	}
}

func TestParseProof_RejectsMissingPrefix(t *testing.T) {
	if _, err := ParseProof("not-v1x0-prefixed"); err == nil {
		t.Fatal("expected an error for a missing v1x0. prefix, got nil")
	}
}

func TestParseProof_RejectsInvalidBase64(t *testing.T) {
	if _, err := ParseProof("v1x0.not valid base64!!"); err == nil {
		t.Fatal("expected an error for invalid base64, got nil")
	}
}

// TestBuildOfflineProofPayloadJSON_FieldOrderIsAlphabeticalNotSourceOrder
// is the regression guard for this section's central gotcha: the payload
// must serialize in alphabetical key order at every nesting level
// (account, dataset, machine; fingerprint before id inside machine), NOT
// the literal "account, machine, dataset" source order this function's own
// map literal is written in.
func TestBuildOfflineProofPayloadJSON_FieldOrderIsAlphabeticalNotSourceOrder(t *testing.T) {
	payloadJSON, err := buildOfflineProofPayloadJSON(
		"00000000-0000-0000-0000-000000000000",
		"00000000-0000-0000-0000-000000000000",
		"fp-abc",
		map[string]any{"b": 1, "a": 2},
	)
	if err != nil {
		t.Fatalf("buildOfflineProofPayloadJSON() error = %v", err)
	}
	rendered := string(payloadJSON)

	accountPos := indexOf(t, rendered, `"account"`)
	datasetPos := indexOf(t, rendered, `"dataset"`)
	machinePos := indexOf(t, rendered, `"machine"`)
	if accountPos >= datasetPos || datasetPos >= machinePos {
		t.Fatalf("top-level field order = %s, want account < dataset < machine (alphabetical)", rendered)
	}

	fingerprintPos := indexOf(t, rendered, `"fingerprint"`)
	idPosInMachine := indexOf(t, rendered[machinePos:], `"id"`) + machinePos
	if fingerprintPos >= idPosInMachine {
		t.Fatalf("machine field order = %s, want fingerprint before id (alphabetical)", rendered)
	}

	aPos := indexOf(t, rendered, `"a":2`)
	bPos := indexOf(t, rendered, `"b":1`)
	if aPos >= bPos {
		t.Fatalf("dataset field order = %s, want a before b (alphabetical, despite map literal writing b first)", rendered)
	}
}

func indexOf(t *testing.T, haystack, needle string) int {
	t.Helper()
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	t.Fatalf("substring %q not found in %q", needle, haystack)
	return -1
}

// TestBuildOfflineProofPayloadJSON_MatchesIndependentlyVerifiedGoldenFixture
// is the byte-exact regression test against testdata/offline_proof_golden.json
// — a fixture whose expected payload_json was hand-constructed
// independently (not derived by calling this SDK's own implementation),
// so this test would catch a field-order drift on refactor that a
// self-referential round-trip test could not.
func TestBuildOfflineProofPayloadJSON_MatchesIndependentlyVerifiedGoldenFixture(t *testing.T) {
	goldenBytes, err := os.ReadFile("testdata/offline_proof_golden.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var golden struct {
		AccountID        string         `json:"account_id"`
		MachineID        string         `json:"machine_id"`
		Fingerprint      string         `json:"fingerprint"`
		Dataset          map[string]any `json:"dataset"`
		PayloadJSON      string         `json:"payload_json"`
		Proof            string         `json:"proof"`
		RSAPubkeySPKIB64 string         `json:"rsa_pubkey_spki_b64"`
	}
	if unmarshalErr := json.Unmarshal(goldenBytes, &golden); unmarshalErr != nil {
		t.Fatalf("json.Unmarshal() error = %v", unmarshalErr)
	}

	got, err := buildOfflineProofPayloadJSON(golden.AccountID, golden.MachineID, golden.Fingerprint, golden.Dataset)
	if err != nil {
		t.Fatalf("buildOfflineProofPayloadJSON() error = %v", err)
	}
	if string(got) != golden.PayloadJSON {
		t.Fatalf("payload_json =\n  %s\nwant\n  %s", got, golden.PayloadJSON)
	}
}

func TestVerifyOfflineProof_SucceedsAgainstGoldenFixture(t *testing.T) {
	goldenBytes, err := os.ReadFile("testdata/offline_proof_golden.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var golden struct {
		AccountID        string         `json:"account_id"`
		MachineID        string         `json:"machine_id"`
		Fingerprint      string         `json:"fingerprint"`
		Dataset          map[string]any `json:"dataset"`
		Proof            string         `json:"proof"`
		RSAPubkeySPKIB64 string         `json:"rsa_pubkey_spki_b64"`
	}
	if unmarshalErr := json.Unmarshal(goldenBytes, &golden); unmarshalErr != nil {
		t.Fatalf("json.Unmarshal() error = %v", unmarshalErr)
	}
	der, err := base64.StdEncoding.DecodeString(golden.RSAPubkeySPKIB64)
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey() error = %v", err)
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("pubkey is %T, want *rsa.PublicKey", pubAny)
	}

	err = VerifyOfflineProof(pub, golden.AccountID, golden.MachineID, golden.Fingerprint, golden.Dataset, golden.Proof)
	if err != nil {
		t.Fatalf("VerifyOfflineProof() error = %v", err)
	}
}

func genRSAKeypairForProofTest(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	return priv
}

func signOfflineProof(t *testing.T, priv *rsa.PrivateKey, payloadJSON []byte) string {
	t.Helper()
	digest := sha256.Sum256(payloadJSON)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
	}
	return ProofPrefix + base64.StdEncoding.EncodeToString(sig)
}

func TestVerifyOfflineProof_RejectsTamperedDataset(t *testing.T) {
	priv := genRSAKeypairForProofTest(t)
	accountID, machineID, fingerprint := "acc-1", "mach-1", "fp-abc"
	signedDataset := map[string]any{"cores": 4}
	payloadJSON, err := buildOfflineProofPayloadJSON(accountID, machineID, fingerprint, signedDataset)
	if err != nil {
		t.Fatalf("buildOfflineProofPayloadJSON() error = %v", err)
	}
	proof := signOfflineProof(t, priv, payloadJSON)

	tamperedDataset := map[string]any{"cores": 999}
	err = VerifyOfflineProof(&priv.PublicKey, accountID, machineID, fingerprint, tamperedDataset, proof)
	if err == nil {
		t.Fatal("VerifyOfflineProof() succeeded against a tampered dataset, want an error")
	}
}

// TestVerifyOfflineProof_RejectsDifferentFieldOrderSignature is the
// regression guard for this section's central gotcha at the Verify layer:
// a signature computed over a manually-reordered (but semantically
// identical) JSON string — the server's literal "account, machine,
// dataset" source order, NOT the canonical alphabetical order this SDK
// reconstructs — must NOT verify against the canonical payload
// VerifyOfflineProof builds.
func TestVerifyOfflineProof_RejectsDifferentFieldOrderSignature(t *testing.T) {
	priv := genRSAKeypairForProofTest(t)
	accountID, machineID, fingerprint := "acc-1", "mach-1", "fp-abc"
	dataset := map[string]any{"cores": 4}

	canonicalJSON, err := buildOfflineProofPayloadJSON(accountID, machineID, fingerprint, dataset)
	if err != nil {
		t.Fatalf("buildOfflineProofPayloadJSON() error = %v", err)
	}
	reorderedJSON := []byte(`{"account":{"id":"` + accountID + `"},"machine":{"id":"` + machineID + `","fingerprint":"` + fingerprint + `"},"dataset":{"cores":4}}`)
	if string(canonicalJSON) == string(reorderedJSON) {
		t.Fatal("test setup bug: canonical and reordered JSON must differ")
	}

	proof := signOfflineProof(t, priv, reorderedJSON) // signed over the WRONG (reordered) bytes
	err = VerifyOfflineProof(&priv.PublicKey, accountID, machineID, fingerprint, dataset, proof)
	if err == nil {
		t.Fatal("VerifyOfflineProof() succeeded against a signature computed over reordered JSON, want an error")
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyOfflineProof_MalformedPrefixRejectedBeforeAnyCrypto(t *testing.T) {
	priv := genRSAKeypairForProofTest(t)
	err := VerifyOfflineProof(&priv.PublicKey, "acc", "mach", "fp", map[string]any{}, "not-v1x0-prefixed")
	if err == nil {
		t.Fatal("expected an error for a malformed proof prefix, got nil")
	}
}

// --- Regression tests added after security review found a second,
// separate byte-exactness gap: Go's encoding/json HTML-escapes
// '<'/'>'/'&' and unconditionally escapes U+2028/U+2029, neither of which
// the Tamga API server's pinned serde_json does by default. See
// buildOfflineProofPayloadJSON's and serdeCompatMarshal's doc comments.

// lineSeparator/paragraphSeparator are built from integer code points
// (not typed as literal escape text) to avoid any ambiguity about their
// exact byte content in this source file.
var lineSeparatorForTest = string(rune(0x2028))
var paragraphSeparatorForTest = string(rune(0x2029))

func TestSerdeCompatMarshal_DoesNotHTMLEscapeAmpersandLtGt(t *testing.T) {
	out, err := serdeCompatMarshal(map[string]any{"note": "AT&T <tag> value"})
	if err != nil {
		t.Fatalf("serdeCompatMarshal() error = %v", err)
	}
	want := `{"note":"AT&T <tag> value"}`
	if string(out) != want {
		t.Fatalf("serdeCompatMarshal() = %s, want %s (must not HTML-escape &/</>, unlike plain json.Marshal)", out, want)
	}
}

func TestSerdeCompatMarshal_DoesNotEscapeLineOrParagraphSeparator(t *testing.T) {
	note := "line one" + lineSeparatorForTest + "line two" + paragraphSeparatorForTest
	out, err := serdeCompatMarshal(map[string]any{"note": note})
	if err != nil {
		t.Fatalf("serdeCompatMarshal() error = %v", err)
	}
	want := `{"note":"line one` + lineSeparatorForTest + `line two` + paragraphSeparatorForTest + `"}`
	if string(out) != want {
		t.Fatalf("serdeCompatMarshal() = %q, want %q (must leave U+2028/U+2029 as raw UTF-8, unlike plain json.Marshal/Encoder)", out, want)
	}
	// Round-trips back to the original value.
	var rt map[string]string
	if err := json.Unmarshal(out, &rt); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if rt["note"] != note {
		t.Fatalf("round-tripped note = %q, want %q", rt["note"], note)
	}
}

// TestSerdeCompatMarshal_LiteralEscapeTextIsNotMisinterpreted is the
// regression guard for the fix's own central risk: a user string
// containing a literal backslash followed by the text "u2028" (not the
// actual U+2028 codepoint) must be encoded as an escaped backslash plus
// plain text, and must round-trip back to the exact original string — a
// naive blind string-replace fix (rejected during implementation) would
// corrupt this case.
func TestSerdeCompatMarshal_LiteralEscapeTextIsNotMisinterpreted(t *testing.T) {
	// The literal 6-byte ASCII sequence backslash/u/2/0/2/8, built from
	// byte literals (not typed as escape-sequence text) so there is no
	// ambiguity about its exact byte content in this source file.
	escapeSequenceText := string([]byte{'\\', 'u', '2', '0', '2', '8'})
	literal := "user typed: " + escapeSequenceText + " as literal text, not a real separator"
	out, err := serdeCompatMarshal(map[string]any{"note": literal})
	if err != nil {
		t.Fatalf("serdeCompatMarshal() error = %v", err)
	}
	var rt map[string]string
	if err := json.Unmarshal(out, &rt); err != nil {
		t.Fatalf("json.Unmarshal() error = %v (output: %s)", err, out)
	}
	if rt["note"] != literal {
		t.Fatalf("round-tripped note = %q, want %q (output was: %s)", rt["note"], literal, out)
	}
}

func TestSerdeCompatMarshal_PlainBackslashRoundTrips(t *testing.T) {
	literal := `a real backslash: \ here, and a quote: "`
	out, err := serdeCompatMarshal(map[string]any{"note": literal})
	if err != nil {
		t.Fatalf("serdeCompatMarshal() error = %v", err)
	}
	var rt map[string]string
	if err := json.Unmarshal(out, &rt); err != nil {
		t.Fatalf("json.Unmarshal() error = %v (output: %s)", err, out)
	}
	if rt["note"] != literal {
		t.Fatalf("round-tripped note = %q, want %q", rt["note"], literal)
	}
}

// TestVerifyOfflineProof_SucceedsWithHTMLSensitiveDatasetCharacters is the
// end-to-end version of the escaping regression: sign and verify a full
// offline proof whose dataset contains '&', '<', '>', and a real
// U+2028 — characters that would previously desync the client's
// reconstructed payload from the server-signed bytes.
func TestVerifyOfflineProof_SucceedsWithHTMLSensitiveDatasetCharacters(t *testing.T) {
	priv := genRSAKeypairForProofTest(t)
	accountID, machineID, fingerprint := "acc-1", "mach-1", "fp-abc"
	dataset := map[string]any{"note": "AT&T <tag> " + lineSeparatorForTest + "end"}

	payloadJSON, err := buildOfflineProofPayloadJSON(accountID, machineID, fingerprint, dataset)
	if err != nil {
		t.Fatalf("buildOfflineProofPayloadJSON() error = %v", err)
	}
	proof := signOfflineProof(t, priv, payloadJSON)

	if err := VerifyOfflineProof(&priv.PublicKey, accountID, machineID, fingerprint, dataset, proof); err != nil {
		t.Fatalf("VerifyOfflineProof() error = %v", err)
	}
}

func TestVerifyOfflineProof_NilPubKeyReturnsErrorNotPanic(t *testing.T) {
	err := VerifyOfflineProof(nil, "acc", "mach", "fp", map[string]any{}, "v1x0.YQ==")
	if err == nil {
		t.Fatal("expected an error for a nil public key, got nil")
	}
}

// ExampleVerifyOfflineProof demonstrates verifying a "v1x0."-prefixed
// offline proof entirely offline, once the account's RSA public key is
// embedded in the calling application. See
// examples/machine_lifecycle/main.go for a full runnable program that
// calls GenerateOfflineProof over the network first.
func ExampleVerifyOfflineProof() {
	priv := genRSAKeypairForExample()
	accountID, machineID, fingerprint := "acc-1", "mach-1", "fp-abc"
	dataset := map[string]any{"cores": 4}

	// A real application receives proof from GenerateOfflineProof; built
	// by hand here so this example has no network dependency.
	payloadJSON, err := buildOfflineProofPayloadJSON(accountID, machineID, fingerprint, dataset)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	digest := sha256.Sum256(payloadJSON)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	proof := ProofPrefix + base64.StdEncoding.EncodeToString(sig)

	err = VerifyOfflineProof(&priv.PublicKey, accountID, machineID, fingerprint, dataset, proof)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("proof verified")
	// Output: proof verified
}

// genRSAKeypairForExample avoids sharing *testing.T-typed
// test helpers with this package-level Example function.
func genRSAKeypairForExample() *rsa.PrivateKey {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return priv
}
