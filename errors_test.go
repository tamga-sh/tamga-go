package tamga

// errors_test.go will hold, per docs/plans/tamga-go.plan.md Section K:
//
//   - ErrorResponse decode from a JSON:API error fixture
//   - errors.Is matches by Code across wrapped/unwrapped forms
//   - errors.As extracts *APIError from a wrapped chain
//
// No tests are implemented yet, though APIError/Error/ErrorResponse
// themselves are already defined in errors.go (not a pure stub — see that
// file's doc comment for why).
