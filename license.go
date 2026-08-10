// license.go will hold the License resource struct (JSON:API license
// attributes), the ValidationMeta struct (TS, Valid, Detail, Code), the
// Scope struct (Product/Policy/User/Environment *uuid.UUID,
// Entitlements []string, Fingerprint/Version/Checksum *string — only the
// first four are enforced server-side today per docs/sdk.md §2), and:
//
//   - ValidateByKey(ctx, key) — POST .../licenses/actions/validate-key
//   - ValidateByID(ctx, licenseID, *ValidateByIDOptions) — POST
//     .../licenses/{id}/actions/validate, with Scope + SkipTouch
//   - QuickValidate(ctx, licenseID) — GET .../licenses/{id}/actions/validate,
//     the flat-JSON special case (no "data" envelope), reusing client.go's
//     dedicated decoder
//   - CheckIn(ctx, licenseID) — POST .../licenses/{id}/actions/check-in, no
//     body, no response meta; maps 422 CHECK_IN_NOT_REQUIRED to a typed
//     sentinel error rather than retrying
//
// Auth is currently unenforced server-side on all three validate endpoints
// (docs/sdk.md's Known Server-Side Gaps item 3) — this SDK still always
// sends Authorization: License <key> so it keeps working once enforcement
// lands.
//
// Not implemented yet — scaffold placeholder. See
// docs/plans/tamga-go.plan.md Sections C and D.
package tamga
