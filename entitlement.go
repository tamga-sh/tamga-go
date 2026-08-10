// entitlement.go will hold the Entitlement resource struct
// (ID/Name/Code/Metadata/Created/Updated), ListEntitlements/GetEntitlement
// (keyset-paginated reads under .../licenses/{id}/entitlements), and the
// HasEntitlement(ctx, licenseID, code) helper backed by a simple in-memory
// TTL cache of the per-license entitlement list.
//
// Despite the URL, these endpoints return full Entitlement resources, not
// lightweight junction records (docs/sdk.md §9). HasEntitlement must match
// on Code (the stable, developer-facing identifier) — never Name, which is
// a display label only and may collide or change independently of Code.
//
// Not implemented yet — scaffold placeholder. See
// docs/plans/tamga-go.plan.md Section J.
package tamga
