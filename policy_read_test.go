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
