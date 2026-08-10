package tamga

import "errors"

// Error models a single JSON:API error object as returned by the Tamga API:
//
//	{"errors": [{id, status, code, title, detail, source: {pointer}}]}
//
// See docs/sdk.md §11. code is stable and should drive matching logic;
// detail is human text and may change between server versions.
type Error struct {
	ID     string       `json:"id,omitempty"`
	Status string       `json:"status,omitempty"`
	Code   string       `json:"code,omitempty"`
	Title  string       `json:"title,omitempty"`
	Detail string       `json:"detail,omitempty"`
	Source *ErrorSource `json:"source,omitempty"`
}

// ErrorSource carries the JSON:API error object's optional source.pointer,
// identifying which part of a request body a validation error applies to.
type ErrorSource struct {
	Pointer string `json:"pointer,omitempty"`
}

// ErrorResponse is the top-level JSON:API error envelope every non-2xx
// response from the API decodes into (except the quick-validate endpoint's
// flat-JSON shape, which is not a JSON:API error and is handled separately
// once client.go's decoder lands).
type ErrorResponse struct {
	Errors []Error `json:"errors"`
}

// APIError wraps a single Error plus the HTTP status it arrived with and
// implements the error interface. This type and its Is/As support are
// scaffolded ahead of client.go's real request execution because nearly
// every other file in this package references APIError or a sentinel error
// in its own doc comments (see docs/plans/tamga-go.plan.md Section K); the
// sentinel error vars themselves (ErrNotFound, ErrFingerprintTaken, etc.)
// are not declared yet and land with the endpoints that can return them.
type APIError struct {
	HTTPStatus int
	Err        Error
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e == nil {
		return "<nil *APIError>"
	}
	return e.Err.Code + ": " + e.Err.Detail
}

// Is reports whether target is an *APIError with the same Code, so that
// errors.Is(err, someSentinel) works regardless of wrapping. Matching is
// deliberately on Code (stable, per docs/sdk.md §11) and never on Detail
// (human text, may change between server versions).
func (e *APIError) Is(target error) bool {
	var t *APIError
	if !errors.As(target, &t) || t == nil {
		return false
	}
	return e.Err.Code == t.Err.Code
}

// As supports errors.As(err, &apiErr) extraction of the concrete *APIError
// from a wrapped error chain.
func (e *APIError) As(target any) bool {
	t, ok := target.(**APIError)
	if !ok {
		return false
	}
	*t = e
	return true
}
