package tamga

// license_test.go will hold, per docs/plans/tamga-go.plan.md Sections C
// and D:
//
//   - ValidateByKey request/response round-trip
//   - ValidateByID with a fully populated Scope
//   - ValidateByID with SkipTouch true/false
//   - ValidateByID with opts == nil sending an empty/absent body
//   - QuickValidate flat-JSON parsing (asserts no "data" key is expected)
//   - Scope with only some fields set serializes with the rest omitted
//     (not null-emitted)
//   - CheckIn success updates last_check_in_at on the returned resource
//   - CheckIn 422 CHECK_IN_NOT_REQUIRED maps to the typed sentinel,
//     errors.Is matches
//   - a godoc Example for ValidateByKey (Section L)
//
// No tests are implemented yet. Fixtures backing these tests will live in
// testdata/validate_by_key_response.json, testdata/validate_by_id_response.json,
// and testdata/quick_validate_response.json.
