// transport.go will hold the AuthTransport interface (Apply(*http.Request))
// and its five concrete implementations, matching the server's try-order
// documented in docs/sdk.md §1:
//
//  1. BearerAuth        — Authorization: Bearer <token>
//  2. BasicAuth          — Authorization: Basic <base64>, three sub-forms:
//     email:password, token: (token as username, empty password),
//     license:<key>
//  3. LicenseKeyAuth     — Authorization: License <key> — the primary
//     transport for embedded/client SDKs; must be this SDK's default
//  4. SessionCookieAuth  — Cookie: Tamga-Session=<uuid>; browser/portal
//     only, requires a matching Origin header, not relevant to non-browser
//     SDKs, implemented here only for completeness
//  5. QueryParamAuth     — ?token=/?auth=
//
// Also owns the Tamga-Version header (sent explicitly on every request,
// defaulting to a pinned SDK version constant — the server's own "1.8"
// default must never be relied on), the Tamga-OTP header (sent when
// WithOTP is configured), and the default User-Agent: tamga-go/<version>.
//
// Tokens are opaque strings: server docs describe tok-/prod-/env-/activ-/
// lic- prefixes by type, but every issued token actually gets the tok-
// prefix regardless of type today — do not build prefix-based type
// detection against that documented-but-unimplemented convention.
//
// Not implemented yet — scaffold placeholder. See
// docs/plans/tamga-go.plan.md Section B.
package tamga
