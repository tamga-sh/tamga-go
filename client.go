// client.go will hold the Client struct (AccountID, BaseURL, an injectable
// *http.Client, and a configured AuthTransport), the functional-options
// constructor New(accountID string, opts ...Option) (*Client, error), the
// Option type and its With* constructors (WithBaseURL, WithHTTPClient,
// WithAPIVersion, WithOTP), the /v1/accounts/{account_id}/... request path
// builder, Content-Type handling (application/vnd.api+json default, with a
// special-cased flat-JSON decoder for the quick-validate endpoint), response
// header readers (Tamga-Version/Tamga-Edition/Tamga-Mode/X-Request-Id), the
// generic JSON:API envelope decode helper, and the core execute() method
// that every other file's methods call through: build request -> apply auth
// transport -> apply headers -> execute -> decode -> map non-2xx to
// errors.go types.
//
// Every public method across the package takes context.Context as its
// first argument.
//
// Explicitly out of scope here (see docs/sdk.md's Known Server-Side Gaps):
// no Tamga-Environment request header, no X-RateLimit-* response header
// parsing.
//
// Not implemented yet — scaffold placeholder. See
// docs/plans/tamga-go.plan.md Section B.
package tamga
