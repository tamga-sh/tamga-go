package tamga

import (
	"context"
	"fmt"
	"time"
)

// EffectiveHeartbeatWindow is the machine heartbeat window this policy
// implies: HeartbeatDuration seconds when the policy sets one, and the
// server's 600-second fallback when it is null. It mirrors the server's
// own Policy::effective_heartbeat_duration_secs, which is what both the
// heartbeat-status computation and the cull job's COALESCE read.
//
// A non-positive HeartbeatDuration also yields the fallback, and that is
// deliberately NOT the one-second floor HeartbeatInterval applies. The
// column carries no CHECK constraint, so an operator can store 0 or a
// negative value, and the server does not rescue it either — the cull
// job's COALESCE(p.heartbeat_duration, 600) replaces NULL only, so a
// stored 0 really is judged as a zero-length window. No ping rate
// satisfies one: with DEAD first read at window+1 seconds, a zero window
// is DEAD from one second after every ping, so flooring to a second here
// would buy nothing and merely spend 200x the request rate failing. This
// returns the one safe number instead, which is the more conservative
// reading of the same rate-bounding rule the floor enforces.
//
// Because HeartbeatDuration counts whole seconds, every value this
// returns is either that fallback or at least one second — there is no
// positive sub-second window to raise. The sub-second value the policy
// path can actually produce is the *interval*, which is why the floor
// lives on HeartbeatInterval below rather than here.
//
// ⚠️ This is the window, not the ping interval. Ping at a fraction of it
// — HeartbeatInterval is window/3, the same ratio DefaultHeartbeatInterval
// uses against the fallback.
func (a PolicyAttributes) EffectiveHeartbeatWindow() time.Duration {
	if a.HeartbeatDuration == nil || *a.HeartbeatDuration <= 0 {
		return machineHeartbeatWindow
	}
	return time.Duration(*a.HeartbeatDuration) * time.Second
}

// HeartbeatInterval is the ping interval this policy calls for:
// EffectiveHeartbeatWindow divided by three, the same ratio
// DefaultHeartbeatInterval applies to the 600s fallback, floored at
// minHeartbeatInterval so a short window can never produce a sub-second
// ping. heartbeat_duration 1 and 2 divide to 333ms and 666ms; both become
// 1s.
//
// Pass it straight to NewHeartbeatScheduler. Doing so is the only way a
// machine on a policy with a short heartbeat_duration stays inside its
// window: DefaultHeartbeatInterval is 200s, computed against the fallback
// alone, so a policy asking for 60s is missed by more than three windows
// per tick and the machine reads DEAD between every ping — and is culled
// outright if that policy also sets require_heartbeat.
//
// The floor costs less than it looks, and the arithmetic is not obvious.
// The server compares age_secs <= window_secs and its num_seconds()
// TRUNCATES, so a machine first reads DEAD at an age of window+1 seconds
// and every window carries one free second. What the floor does cost is
// the divisor's promise of two tolerable consecutive losses, and it
// degrades gracefully rather than breaking:
//
//	heartbeat_duration | interval | DEAD at age | consecutive losses tolerated
//	               600 |     200s |        601s | 2
//	                 3 |       1s |          4s | 2  — floor and divisor first agree
//	                 2 |       1s |          3s | 1
//	                 1 |       1s |          2s | 0  — still served; one ping must land
//	                 0 |     200s |          1s | not held (see EffectiveHeartbeatWindow)
//
// So the value the floor cannot serve is 0, not 1. Do not add a
// window-aware floor to chase it: serving a zero window needs a ~333ms
// ping, which would tie this SDK's request rate to num_seconds()
// truncation — a server implementation artifact, not a protocol
// guarantee — for one nonsensical setting.
func (a PolicyAttributes) HeartbeatInterval() time.Duration {
	if interval := a.EffectiveHeartbeatWindow() / 3; interval > minHeartbeatInterval {
		return interval
	}
	return minHeartbeatInterval
}

// GetPolicy reads a policy by ID.
// GET /v1/accounts/{account_id}/policies/{policy_id}.
//
// ⚠️ Not callable with a license key. This route authorizes on the
// policy.read permission, and policy.read is NOT in the LicenseToken
// role's default permission set — so a client built with WithLicenseKey
// gets 403 FORBIDDEN here unconditionally, however the policy itself is
// configured. That is a role gap, not a policy setting, so nothing an
// operator can change on the license fixes it.
//
// Use GetLicensePolicy instead from an embedded client: it returns the
// same policies resource, resolved through the license, and authorizes on
// license.read, which a LicenseToken does hold. Reach for this method
// only when authenticating with a BearerAuth token whose role carries
// policy.read.
func (c *Client) GetPolicy(ctx context.Context, policyID string) (*Policy, error) {
	policy, err := decodeJSONAPI[Policy](ctx, c, "GET", fmt.Sprintf("/policies/%s", escapePathSegment(policyID)), nil)
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

// GetLicensePolicy reads the policy a license is issued under.
// GET /v1/accounts/{account_id}/licenses/{license_id}/policy.
//
// This is the policy read an embedded client should use. It returns the
// identical policies resource GetPolicy does — the handler resolves the
// license, then serializes its policy with the same serializer — but it
// authorizes on license.read rather than policy.read, and license.read is
// in the LicenseToken permission set while policy.read is not. Under
// WithLicenseKey this route works and GetPolicy does not.
//
// The main reason to call it is to size a heartbeat scheduler correctly:
// PolicyAttributes.HeartbeatInterval turns the returned policy into the
// interval to hand NewHeartbeatScheduler. HeartbeatIntervalForLicense
// does both steps in one call.
//
// ⚠️ Two of the returned enums need care. OverageStrategyRaw and
// HeartbeatResurrectionStrategyRaw are raw strings whose real-world
// defaults ("DENY_ACCESS", "NO_RESURRECTION") are not real variants —
// pass them through EffectiveOverageStrategy/EffectiveResurrectionStrategy
// rather than comparing them directly. And CheckInInterval's constants in
// this package spell the wire values as "day"/"week"/"month"/"year" while
// the server's column permits only "daily"/"weekly"/"monthly"/"yearly";
// decoding is unaffected because CheckInInterval is a plain string type,
// but a direct comparison against CheckInIntervalDay and friends will not
// match a real policy. Compare against the adverbial spelling until that
// is corrected.
func (c *Client) GetLicensePolicy(ctx context.Context, licenseID string) (*Policy, error) {
	policy, err := decodeJSONAPI[Policy](ctx, c, "GET", fmt.Sprintf("/licenses/%s/policy", escapePathSegment(licenseID)), nil)
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

// GetLicense reads a license by ID.
// GET /v1/accounts/{account_id}/licenses/{license_id}.
//
// Returns the full License resource — the same shape ValidateByID returns
// alongside its ValidationMeta — without running validation and without
// touching last_validated_at. Use it to read the current status,
// machines_count or expiry; use ValidateByID when the answer needs to be
// a verdict.
//
// ⚠️ Do not describe this route as license-scoped. The server applies
// require_license_scope to exactly five routes — validate, validate-key,
// quick-validate and the two check-outs — and this is not one of them,
// while attributes.key comes back in plaintext. A license key can
// therefore read any license in the account, including its key. The
// exposure is server-side and filed upstream; this SDK cannot fix it and
// must not paper over it.
func (c *Client) GetLicense(ctx context.Context, licenseID string) (*License, error) {
	license, err := decodeJSONAPI[License](ctx, c, "GET", fmt.Sprintf("/licenses/%s", escapePathSegment(licenseID)), nil)
	if err != nil {
		return nil, err
	}
	return &license, nil
}

// HeartbeatIntervalForLicense reads the policy behind licenseID and
// returns the ping interval it calls for — GetLicensePolicy followed by
// PolicyAttributes.HeartbeatInterval.
//
// This is how a scheduler learns its real window without guessing:
//
//	interval, err := client.HeartbeatIntervalForLicense(ctx, licenseID)
//	if err != nil {
//		interval = tamga.DefaultHeartbeatInterval // 600s fallback / 3
//	}
//	go tamga.NewHeartbeatScheduler(client, machineID, interval).Run(ctx)
//
// ⚠️ Do not try to derive the window from a Machine's NextHeartbeatAt
// instead. That field means different things depending on which route
// produced it — the ping and reset routes compute it against the 600s
// fallback, the read routes against the policy — and a client holding a
// Machine cannot tell which kind it has. The endpoint a scheduler
// naturally calls is the one that is wrong. Read the policy.
//
// Called once at startup. The window is a policy setting, not a runtime
// value, so there is nothing to poll.
func (c *Client) HeartbeatIntervalForLicense(ctx context.Context, licenseID string) (time.Duration, error) {
	policy, err := c.GetLicensePolicy(ctx, licenseID)
	if err != nil {
		return 0, err
	}
	return policy.Attributes.HeartbeatInterval(), nil
}
