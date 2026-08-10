package tamga

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func TestErrorResponse_DecodeFromFixture(t *testing.T) {
	raw := `{"errors":[{"id":"01926b3e-0000-7000-8000-000000000000","status":"404","code":"NOT_FOUND","title":"Not Found","detail":"The requested license was not found"}]}`
	var resp ErrorResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(resp.Errors) != 1 {
		t.Fatalf("len(Errors) = %d, want 1", len(resp.Errors))
	}
	if resp.Errors[0].Code != "NOT_FOUND" || resp.Errors[0].Status != "404" {
		t.Errorf("Errors[0] = %+v", resp.Errors[0])
	}
}

func TestErrorResponse_DecodesSourcePointer(t *testing.T) {
	raw := `{"errors":[{"id":"e1","status":"422","code":"DATASET_INVALID","title":"Unprocessable Entity","detail":"dataset must be an object","source":{"pointer":"/meta/dataset"}}]}`
	var resp ErrorResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if resp.Errors[0].Source == nil || resp.Errors[0].Source.Pointer != "/meta/dataset" {
		t.Errorf("Source = %+v", resp.Errors[0].Source)
	}
}

func TestAPIError_IsMatchesByCodeAcrossWrapping(t *testing.T) {
	base := &APIError{HTTPStatus: 409, Err: Error{Code: "FINGERPRINT_TAKEN", Detail: "specific detail text"}}
	wrapped := fmt.Errorf("create machine: %w", base)

	if !errors.Is(base, ErrFingerprintTaken) {
		t.Error("errors.Is(base, ErrFingerprintTaken) = false, want true")
	}
	if !errors.Is(wrapped, ErrFingerprintTaken) {
		t.Error("errors.Is(wrapped, ErrFingerprintTaken) = false, want true (must match through fmt.Errorf %w wrapping)")
	}
	if errors.Is(base, ErrPIDTaken) {
		t.Error("errors.Is(base, ErrPIDTaken) = true, want false (different code)")
	}
}

func TestAPIError_IsIgnoresDetailDifferences(t *testing.T) {
	a := &APIError{HTTPStatus: 404, Err: Error{Code: "NOT_FOUND", Detail: "license abc not found"}}
	b := &APIError{HTTPStatus: 404, Err: Error{Code: "NOT_FOUND", Detail: "completely different wording"}}
	if !a.Is(b) {
		t.Error("Is() should match on Code alone, ignoring Detail")
	}
}

func TestAPIError_AsExtractsFromWrappedChain(t *testing.T) {
	base := &APIError{HTTPStatus: 500, Err: Error{Code: "INTERNAL_SERVER_ERROR"}}
	wrapped := fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", base))

	var target *APIError
	if !errors.As(wrapped, &target) {
		t.Fatal("errors.As() = false, want true")
	}
	if target != base {
		t.Errorf("target = %v, want the original *APIError", target)
	}
}

func TestAPIError_ErrorMessageFormat(t *testing.T) {
	err := &APIError{Err: Error{Code: "NOT_FOUND", Detail: "no such license"}}
	want := "NOT_FOUND: no such license"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
