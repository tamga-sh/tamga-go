package tamga

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

const representativePolicyJSON = `{
	"id":"pol-id","type":"policies",
	"attributes":{
		"product_id":"prod-1","name":"Standard","duration":null,"strict":false,"floating":false,
		"scheme":null,"encrypted":false,"use_pool":false,"protected":false,
		"require_check_in":false,"check_in_interval":"weekly","check_in_interval_count":1,
		"require_heartbeat":true,"heartbeat_duration":90,
		"heartbeat_cull_strategy":"DEACTIVATE_DEAD",
		"heartbeat_resurrection_strategy":"NO_RESURRECTION",
		"machine_uniqueness_strategy":"UNIQUE_PER_LICENSE",
		"expiration_strategy":"RESTRICT_ACCESS","expiration_basis":"FROM_CREATION",
		"renewal_basis":"FROM_EXPIRY","authentication_strategy":"LICENSE",
		"overage_strategy":"DENY_ACCESS","max_machines":5,"max_cores":null,"max_uses":null,
		"max_processes":10,"max_users":null,"metadata":{},
		"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"
	}
}`

func TestEffectiveHeartbeatWindow(t *testing.T) {
	secs := func(n int32) *int32 { return &n }
	tests := []struct {
		duration *int32
		name     string
		want     time.Duration
	}{
		{secs(90), "policy sets a shorter window", 90 * time.Second},
		{secs(1800), "policy sets a longer window", 1800 * time.Second},
		{nil, "null falls back to the server default", 600 * time.Second},
		{secs(0), "zero falls back rather than yielding a zero interval", 600 * time.Second},
		{secs(-5), "negative falls back", 600 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs := PolicyAttributes{HeartbeatDuration: tc.duration}
			if got := attrs.EffectiveHeartbeatWindow(); got != tc.want {
				t.Errorf("EffectiveHeartbeatWindow() = %v, want %v", got, tc.want)
			}
			if got := attrs.HeartbeatInterval(); got != tc.want/3 {
				t.Errorf("HeartbeatInterval() = %v, want %v", got, tc.want/3)
			}
			// A zero interval would panic time.NewTicker; the scheduler's
			// own guard must never be the only thing standing between a
			// misconfigured policy and that panic.
			if attrs.HeartbeatInterval() <= 0 {
				t.Error("HeartbeatInterval() is non-positive")
			}
		})
	}
}

func TestHeartbeatInterval_IsTighterThanTheDefaultOnAShortPolicy(t *testing.T) {
	short := int32(90)
	attrs := PolicyAttributes{HeartbeatDuration: &short}
	if attrs.HeartbeatInterval() >= DefaultHeartbeatInterval {
		t.Fatalf("HeartbeatInterval() = %v, not tighter than DefaultHeartbeatInterval (%v) — "+
			"the whole point of reading the policy is that the 600s-derived default pings too slowly",
			attrs.HeartbeatInterval(), DefaultHeartbeatInterval)
	}
}

func TestGetLicensePolicy_UsesTheLicenseScopedRoute(t *testing.T) {
	var gotPath string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + representativePolicyJSON + `}`))
	})
	defer closeFn()

	policy, err := c.GetLicensePolicy(context.Background(), "lic-1")
	if err != nil {
		t.Fatalf("GetLicensePolicy() error = %v", err)
	}
	if gotPath != "/v1/accounts/acct-123/licenses/lic-1/policy" {
		t.Errorf("path = %s", gotPath)
	}
	if policy.Attributes.HeartbeatDuration == nil || *policy.Attributes.HeartbeatDuration != 90 {
		t.Fatalf("HeartbeatDuration = %v", policy.Attributes.HeartbeatDuration)
	}
	// The two raw-string fields must survive decoding untouched so the
	// Effective* helpers can normalize the bogus server defaults.
	if policy.Attributes.OverageStrategyRaw != "DENY_ACCESS" {
		t.Errorf("OverageStrategyRaw = %q", policy.Attributes.OverageStrategyRaw)
	}
	if EffectiveOverageStrategy(policy.Attributes.OverageStrategyRaw) != OverageNone {
		t.Error("EffectiveOverageStrategy did not normalize the bogus DENY_ACCESS default")
	}
	if EffectiveResurrectionStrategy(policy.Attributes.HeartbeatResurrectionStrategyRaw) != HeartbeatResurrectionNone {
		t.Error("EffectiveResurrectionStrategy did not normalize the bogus NO_RESURRECTION default")
	}
}

// The server's check_in_interval column permits only the adverbial
// spellings. This SDK's CheckInInterval constants still carry the noun
// spellings, so a real policy decodes cleanly (it is a plain string type)
// but does not compare equal to them. Pin that gap so correcting the
// constants is a deliberate, visible change rather than a silent one.
func TestGetLicensePolicy_CheckInIntervalDecodesTheAdverbialWireValue(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + representativePolicyJSON + `}`))
	})
	defer closeFn()

	policy, err := c.GetLicensePolicy(context.Background(), "lic-1")
	if err != nil {
		t.Fatalf("GetLicensePolicy() error = %v", err)
	}
	if policy.Attributes.CheckInInterval == nil {
		t.Fatal("CheckInInterval = nil")
	}
	if got := *policy.Attributes.CheckInInterval; got != "weekly" {
		t.Errorf("CheckInInterval = %q, want the server's adverbial spelling", got)
	}
	if *policy.Attributes.CheckInInterval == CheckInIntervalWeek {
		t.Error("CheckInIntervalWeek now matches the wire value; update this test and the doc comments that warn it does not")
	}
}

func TestGetPolicy_UsesThePolicyRouteAndSurfacesA403(t *testing.T) {
	var gotPath string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":[{"status":"403","code":"FORBIDDEN","title":"Forbidden","detail":"missing policy.read"}]}`))
	})
	defer closeFn()

	// policy.read is not in the LicenseToken permission set, so this is
	// what a WithLicenseKey client always gets here.
	_, err := c.GetPolicy(context.Background(), "pol-id")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("errors.Is(err, ErrForbidden) = false, err = %v", err)
	}
	if gotPath != "/v1/accounts/acct-123/policies/pol-id" {
		t.Errorf("path = %s", gotPath)
	}
}

func TestGetLicense_ReadsWithoutValidating(t *testing.T) {
	var gotPath, gotMethod string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + representativeLicenseJSON + `}`))
	})
	defer closeFn()

	license, err := c.GetLicense(context.Background(), "lic-id")
	if err != nil {
		t.Fatalf("GetLicense() error = %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %s, want GET — this route must not be confused with the POST validate", gotMethod)
	}
	if gotPath != "/v1/accounts/acct-123/licenses/lic-id" {
		t.Errorf("path = %s", gotPath)
	}
	if license.Attributes.Status != "ACTIVE" {
		t.Errorf("Status = %q", license.Attributes.Status)
	}
}

func TestHeartbeatIntervalForLicense_DerivesTheIntervalFromThePolicy(t *testing.T) {
	var gotPath string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + representativePolicyJSON + `}`))
	})
	defer closeFn()

	interval, err := c.HeartbeatIntervalForLicense(context.Background(), "lic-1")
	if err != nil {
		t.Fatalf("HeartbeatIntervalForLicense() error = %v", err)
	}
	if interval != 30*time.Second {
		t.Errorf("interval = %v, want 30s (a 90s policy window / 3)", interval)
	}
	// It must go through the license-scoped route, not /policies/{id},
	// which 403s under license-key auth.
	if gotPath != "/v1/accounts/acct-123/licenses/lic-1/policy" {
		t.Errorf("path = %s", gotPath)
	}
	// And it must be usable directly by the scheduler.
	if got := NewHeartbeatScheduler(c, "mach-1", interval).interval; got != interval {
		t.Errorf("scheduler interval = %v, want %v", got, interval)
	}
}

func TestHeartbeatIntervalForLicense_PropagatesTheError(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"status":"404","code":"NOT_FOUND","title":"Not Found","detail":"no license"}]}`))
	})
	defer closeFn()

	interval, err := c.HeartbeatIntervalForLicense(context.Background(), "lic-1")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("errors.Is(err, ErrNotFound) = false, err = %v", err)
	}
	if interval != 0 {
		t.Errorf("interval = %v, want 0 so a caller cannot mistake it for a real window", interval)
	}
}

// tolerableConsecutiveLosses reports how many pings in a row a machine can
// miss — pinging every interval, against a server window of windowSecs —
// and still have the next successful ping land before the server reads
// DEAD. It returns -1 when no number of losses is tolerable because even
// an unbroken ping schedule cannot stay inside the window.
//
// The whole calculation turns on one server-side detail:
// heartbeat_status_within compares age_secs <= window_secs and its
// num_seconds() TRUNCATES (Duration::milliseconds(1999).num_seconds() ==
// 1), so DEAD is first read at an age of windowSecs+1 seconds, not
// windowSecs. Every window carries one free second. After k lost pings the
// next success lands at an age of (k+1)*interval, so the answer is the
// largest k for which (k+1)*interval is still under that deadline.
func tolerableConsecutiveLosses(interval time.Duration, windowSecs int) int {
	deadAt := time.Duration(windowSecs+1) * time.Second
	k := 0
	for time.Duration(k+1)*interval < deadAt {
		k++
	}
	return k - 1
}

// TestPolicyHeartbeatInterval_LossesTolerablePerWindow pins what the
// one-second interval floor actually costs, window by window, against the
// windows a policy can express.
//
// The floor's price is not a broken window — it is the interval divisor's
// promise of two tolerable consecutive losses, and that degrades
// gracefully. heartbeat_duration 3 is where the floor and the divisor first
// agree and the promise still holds in full; 2 tolerates one loss; 1
// tolerates none but is still genuinely served, because a 1s window pinged
// every 1s has two seconds of slack rather than zero. The value the floor
// cannot hold is 0, not 1 — the opposite of what the objection to the floor
// predicted.
//
// ⚠️ STANDING CAVEAT — this is the test that fails first. Every "losses"
// number below rests on num_seconds() truncating, which is what puts DEAD
// at windowSecs+1 and hands each window its free second. If the server
// ever compares sub-second, DEAD moves to windowSecs, every row here loses
// one from its count, window 0 becomes unserveable at any ping rate at all,
// and window 1 stops being comfortably served and becomes a genuine
// boundary case — a ping landing exactly at the deadline. Truncation is a
// server implementation artifact, not a protocol guarantee. If this test
// goes red, re-derive the floor before touching the expectations.
func TestPolicyHeartbeatInterval_LossesTolerablePerWindow(t *testing.T) {
	secs := func(n int32) *int32 { return &n }
	tests := []struct {
		duration *int32
		name     string
		// serverWindowSecs is the window the SERVER judges against, which
		// is not always the one this SDK schedules against — see the
		// heartbeat_duration 0 row.
		serverWindowSecs int
		wantInterval     time.Duration
		wantLosses       int
	}{
		{secs(600), "600 — the fallback window, stated explicitly", 600, 200 * time.Second, 2},
		{secs(3), "3 — where the floor and the divisor first agree", 3, time.Second, 2},
		{secs(2), "2 — floored from 666ms, tolerates one loss", 2, time.Second, 1},
		{secs(1), "1 — floored from 333ms, served with no slack for a loss", 1, time.Second, 0},
		{secs(0), "0 — the one window no ping rate can hold", 0, DefaultHeartbeatInterval, -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs := PolicyAttributes{HeartbeatDuration: tc.duration}

			if got := attrs.HeartbeatInterval(); got != tc.wantInterval {
				t.Errorf("HeartbeatInterval() = %v, want %v", got, tc.wantInterval)
			}
			// The floor's actual invariant: nothing this package derives
			// from a policy is ever handed to a time.Ticker sub-second.
			if got := attrs.HeartbeatInterval(); got < time.Second {
				t.Errorf("HeartbeatInterval() = %v, below the one-second floor", got)
			}
			if got := tolerableConsecutiveLosses(tc.wantInterval, tc.serverWindowSecs); got != tc.wantLosses {
				t.Errorf("tolerableConsecutiveLosses(%v, %ds) = %d, want %d",
					tc.wantInterval, tc.serverWindowSecs, got, tc.wantLosses)
			}
		})
	}
}

// TestPolicyHeartbeatInterval_ZeroWindowFallsBackRatherThanFloodingForIt
// records why heartbeat_duration 0 keeps the 600s fallback instead of
// being floored to a 1s ping like every other short window.
//
// The server does not rescue a stored 0 — the cull job's
// COALESCE(p.heartbeat_duration, 600) replaces NULL only — so a 0 window
// really is judged as zero-length, and a machine on it reads DEAD from one
// second after every ping no matter how fast the SDK pings. Since the
// window cannot be held either way, the only property left to preserve is
// the request rate, which is what the floor exists to bound in the first
// place. Pinging every second forever to fail is strictly worse than
// pinging every 200s to fail.
//
// Serving it for real would need a ~333ms ping, which would tie this SDK's
// request rate to num_seconds() truncation for one nonsensical setting.
// Don't.
func TestPolicyHeartbeatInterval_ZeroWindowFallsBackRatherThanFloodingForIt(t *testing.T) {
	zero := int32(0)
	attrs := PolicyAttributes{HeartbeatDuration: &zero}

	if got := attrs.EffectiveHeartbeatWindow(); got != 600*time.Second {
		t.Errorf("EffectiveHeartbeatWindow() = %v, want the 600s fallback", got)
	}
	if got := attrs.HeartbeatInterval(); got != DefaultHeartbeatInterval {
		t.Errorf("HeartbeatInterval() = %v, want %v (the fallback-derived default), "+
			"not a 1s flood against a window that cannot be held at any rate",
			got, DefaultHeartbeatInterval)
	}
}
