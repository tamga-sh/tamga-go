package tamga

// entitlement_test.go will hold, per docs/plans/tamga-go.plan.md Section J:
//
//   - ListEntitlements pagination
//   - GetEntitlement single fetch
//   - HasEntitlement matches on Code even when Name differs or collides
//     with another entitlement's code
//   - HasEntitlement cache hit avoids a second HTTP call within the TTL
//   - a godoc Example for HasEntitlement (Section L)
//
// No tests are implemented yet.
