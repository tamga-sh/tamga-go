package tamga

import (
	"encoding/json"
	"testing"
)

func allKnownValidationCodes() []ValidationCode {
	return []ValidationCode{
		ValidationCodeValid, ValidationCodeNotFound, ValidationCodeBanned,
		ValidationCodeSuspended, ValidationCodeExpired, ValidationCodeOverdue,
		ValidationCodeEntitlementsMissing, ValidationCodeTooManyMachines,
		ValidationCodeTooManyCores, ValidationCodeTooMuchMemory, ValidationCodeTooMuchDisk,
		ValidationCodeTooManyProcesses, ValidationCodeTooManyUsers, ValidationCodeHeartbeatDead,
		ValidationCodeHeartbeatNotStarted, ValidationCodeProductScopeMismatch,
		ValidationCodePolicyScopeMismatch, ValidationCodeUserScopeMismatch,
		ValidationCodeFingerprintScopeMismatch, ValidationCodeComponentsScopeMismatch,
		ValidationCodeChecksumScopeMismatch, ValidationCodeVersionScopeMismatch,
		ValidationCodeEnvironmentScopeMismatch, ValidationCodeTooManyUses,
	}
}

func TestValidationCode_JSONRoundTripAll24Values(t *testing.T) {
	codes := allKnownValidationCodes()
	if len(codes) != 24 {
		t.Fatalf("len(codes) = %d, want 24", len(codes))
	}
	for _, code := range codes {
		encoded, err := json.Marshal(code)
		if err != nil {
			t.Fatalf("Marshal(%v) error = %v", code, err)
		}
		var decoded ValidationCode
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("Unmarshal(%s) error = %v", encoded, err)
		}
		if decoded != code {
			t.Errorf("round-trip %v -> %s -> %v", code, encoded, decoded)
		}
	}
}

func TestValidationCode_UnknownValuePassthrough(t *testing.T) {
	var code ValidationCode
	if err := json.Unmarshal([]byte(`"SOME_FUTURE_CODE"`), &code); err != nil {
		t.Fatalf("Unmarshal() error = %v, want no error (lenient passthrough)", err)
	}
	if code != ValidationCode("SOME_FUTURE_CODE") {
		t.Errorf("code = %v, want SOME_FUTURE_CODE", code)
	}
}

func TestValidationMeta_DecodesRepresentativeResponse(t *testing.T) {
	raw := `{"ts":"2026-01-01T00:00:00Z","valid":true,"detail":"is valid","code":"VALID"}`
	var meta ValidationMeta
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !meta.Valid || meta.Detail != "is valid" || meta.Code != ValidationCodeValid {
		t.Errorf("meta = %+v", meta)
	}
}
