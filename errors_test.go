package tamga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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

// The API renders status as a string (StatusCode::as_u16().to_string()) and
// every fixture above says so. D18: a decoder that accepts only that
// representation fails the whole envelope on a number, and the failure
// surfaces as a synthetic UNKNOWN that hides the real code.
func TestErrorResponse_DecodesStatusAsStringOrNumber(t *testing.T) {
	tests := map[string]string{
		// Exact wire shape from the API plan, both representations.
		"string": `{"errors":[{"id":"e1","status":"422","code":"SIGNING_KEY_MISSING","title":"Unprocessable Entity","detail":"the account has no signing key"}]}`,
		"number": `{"errors":[{"id":"e1","status":422,"code":"SIGNING_KEY_MISSING","title":"Unprocessable Entity","detail":"the account has no signing key"}]}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			var resp ErrorResponse
			if err := json.Unmarshal([]byte(raw), &resp); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			if len(resp.Errors) != 1 {
				t.Fatalf("len(Errors) = %d, want 1", len(resp.Errors))
			}
			got := resp.Errors[0]
			if got.Status != "422" || got.Code != "SIGNING_KEY_MISSING" || got.ID != "e1" ||
				got.Title != "Unprocessable Entity" || got.Detail != "the account has no signing key" {
				t.Errorf("Errors[0] = %+v", got)
			}
		})
	}
}

func TestErrorResponse_RejectsANonScalarStatus(t *testing.T) {
	var resp ErrorResponse
	if err := json.Unmarshal([]byte(`{"errors":[{"status":{"code":422},"code":"X"}]}`), &resp); err == nil {
		t.Fatal("Unmarshal() = nil, want an error for an object-valued status")
	}
}

// Exact wire shape from the API plan: FINGERPRINT_TAKEN carries
// meta.machineId only when the existing machine is on the requested license.
func TestErrorResponse_DecodesMeta(t *testing.T) {
	raw := `{"errors":[{"id":"e1","status":"409","code":"FINGERPRINT_TAKEN","title":"Conflict","detail":"already activated","meta":{"machineId":"01926b3e-0000-7000-8000-0000000000aa"}}]}`
	var resp ErrorResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got := resp.Errors[0].Meta["machineId"]; got != "01926b3e-0000-7000-8000-0000000000aa" {
		t.Errorf("Meta[machineId] = %v", got)
	}
	if resp.Errors[0].Source != nil || resp.Errors[0].Detail != "already activated" {
		t.Errorf("sibling fields drifted: %+v", resp.Errors[0])
	}

	withoutMeta := `{"errors":[{"status":"409","code":"FINGERPRINT_TAKEN","detail":"cross-license"}]}`
	if err := json.Unmarshal([]byte(withoutMeta), &resp); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if resp.Errors[0].Meta != nil {
		t.Errorf("Meta = %v, want nil when the server sent none", resp.Errors[0].Meta)
	}
}

func TestAPIError_ConflictingMachineID(t *testing.T) {
	tests := []struct {
		name   string
		err    *APIError
		wantID string
		wantOK bool
	}{
		{"same-license conflict", &APIError{HTTPStatus: 409, Err: Error{Code: "FINGERPRINT_TAKEN", Meta: map[string]any{"machineId": "m-1"}}}, "m-1", true},
		{"cross-license conflict has no meta", &APIError{HTTPStatus: 409, Err: Error{Code: "FINGERPRINT_TAKEN"}}, "", false},
		{"empty id", &APIError{HTTPStatus: 409, Err: Error{Code: "FINGERPRINT_TAKEN", Meta: map[string]any{"machineId": ""}}}, "", false},
		{"non-string id", &APIError{HTTPStatus: 409, Err: Error{Code: "FINGERPRINT_TAKEN", Meta: map[string]any{"machineId": 42}}}, "", false},
		{"other code with meta", &APIError{HTTPStatus: 409, Err: Error{Code: "KEY_TAKEN", Meta: map[string]any{"machineId": "m-1"}}}, "", false},
		{"nil receiver", nil, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := tc.err.ConflictingMachineID()
			if id != tc.wantID || ok != tc.wantOK {
				t.Errorf("ConflictingMachineID() = (%q, %v), want (%q, %v)", id, ok, tc.wantID, tc.wantOK)
			}
		})
	}
}

func TestAPIError_MeterEntitlementID(t *testing.T) {
	tests := []struct {
		name   string
		err    *APIError
		wantID string
		wantOK bool
	}{
		{"meter cap hit", &APIError{HTTPStatus: 422, Err: Error{Code: "METER_LIMIT_EXCEEDED", Meta: map[string]any{"entitlement_id": "ent-1"}}}, "ent-1", true},
		{"no meta", &APIError{HTTPStatus: 422, Err: Error{Code: "METER_LIMIT_EXCEEDED"}}, "", false},
		{"empty id", &APIError{HTTPStatus: 422, Err: Error{Code: "METER_LIMIT_EXCEEDED", Meta: map[string]any{"entitlement_id": ""}}}, "", false},
		{"non-string id", &APIError{HTTPStatus: 422, Err: Error{Code: "METER_LIMIT_EXCEEDED", Meta: map[string]any{"entitlement_id": 42}}}, "", false},
		{"other code with meta", &APIError{HTTPStatus: 409, Err: Error{Code: "FINGERPRINT_TAKEN", Meta: map[string]any{"entitlement_id": "ent-1"}}}, "", false},
		{"nil receiver", nil, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := tc.err.MeterEntitlementID()
			if id != tc.wantID || ok != tc.wantOK {
				t.Errorf("MeterEntitlementID() = (%q, %v), want (%q, %v)", id, ok, tc.wantID, tc.wantOK)
			}
		})
	}
}

func TestSentinels_SigningAndSecretKeyMissingMatchByCode(t *testing.T) {
	for code, sentinel := range map[string]*APIError{
		"SIGNING_KEY_MISSING": ErrSigningKeyMissing,
		"SECRET_KEY_MISSING":  ErrSecretKeyMissing,
	} {
		got := newAPIErrorFromResponse(422, ErrorResponse{Errors: []Error{{Code: code, Status: "422", Detail: "x"}}})
		if !errors.Is(got, sentinel) {
			t.Errorf("errors.Is(%s) = false", code)
		}
		if sentinel.HTTPStatus != 422 {
			t.Errorf("%s sentinel HTTPStatus = %d, want 422", code, sentinel.HTTPStatus)
		}
	}
}

func TestErrMeterLimitExceeded_MatchesByCode(t *testing.T) {
	got := newAPIErrorFromResponse(422, ErrorResponse{Errors: []Error{{Code: "METER_LIMIT_EXCEEDED", Status: "422", Detail: "meter cap exceeded"}}})
	if !errors.Is(got, ErrMeterLimitExceeded) {
		t.Error("errors.Is(got, ErrMeterLimitExceeded) = false")
	}
	if ErrMeterLimitExceeded.HTTPStatus != 422 {
		t.Errorf("ErrMeterLimitExceeded.HTTPStatus = %d, want 422", ErrMeterLimitExceeded.HTTPStatus)
	}
}

// End to end through mapError: a numeric status must not degrade the
// envelope to UNKNOWN and lose the code.
func TestMapError_NumericStatusKeepsTheServersCode(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"errors":[{"id":"e1","status":422,"code":"SIGNING_KEY_MISSING","title":"Unprocessable Entity","detail":"no signing key"}]}`))
	})
	defer closeFn()

	_, err := c.CheckOutLicense(context.Background(), "lic-1", CheckOutOptions{})
	if !errors.Is(err, ErrSigningKeyMissing) {
		t.Fatalf("errors.Is(err, ErrSigningKeyMissing) = false, err = %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Err.Status != "422" {
		t.Errorf("Err.Status = %q, want \"422\"", apiErr.Err.Status)
	}
}
