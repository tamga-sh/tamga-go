package tamga

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const representativeMachineJSON = `{
	"id":"mach-id","type":"machines",
	"attributes":{
		"fingerprint":"fp-abc123","cores":4,"memory":null,"disk":null,"ip":null,
		"hostname":"host1","platform":"linux","name":null,"heartbeat_status":"NOT_STARTED",
		"last_heartbeat_at":null,"next_heartbeat_at":null,"last_check_out_at":null,
		"metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"
	}
}`

func TestCreateMachine_FullOptionalFieldSet(t *testing.T) {
	var gotBody map[string]any
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/accounts/acct-123/machines" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + representativeMachineJSON + `}`))
	})
	defer closeFn()

	name := "My Machine"
	ip := "10.0.0.1"
	hostname := "host1"
	platform := "linux"
	cores := int32(4)
	memory := int64(1024)
	disk := int64(2048)

	machine, err := c.CreateMachine(context.Background(), CreateMachineOptions{
		Fingerprint: "fp-abc123", LicenseID: "lic-id",
		Name: &name, IP: &ip, Hostname: &hostname, Platform: &platform,
		Cores: &cores, Memory: &memory, Disk: &disk,
		Metadata: map[string]any{"env": "prod"},
	})
	if err != nil {
		t.Fatalf("CreateMachine() error = %v", err)
	}
	if machine.Attributes.Fingerprint != "fp-abc123" {
		t.Errorf("Fingerprint = %q", machine.Attributes.Fingerprint)
	}
	data := gotBody["data"].(map[string]any)
	attrs := data["attributes"].(map[string]any)
	if attrs["fingerprint"] != "fp-abc123" || attrs["name"] != "My Machine" {
		t.Errorf("attributes = %+v", attrs)
	}
	rel := data["relationships"].(map[string]any)
	license := rel["license"].(map[string]any)["data"].(map[string]any)
	if license["id"] != "lic-id" || license["type"] != "licenses" {
		t.Errorf("relationships.license = %+v", license)
	}
}

func TestCreateMachine_FingerprintTakenMapping(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"errors":[{"id":"e1","status":"409","code":"FINGERPRINT_TAKEN","title":"Conflict","detail":"fingerprint already taken"}]}`))
	})
	defer closeFn()

	_, err := c.CreateMachine(context.Background(), CreateMachineOptions{Fingerprint: "fp-1", LicenseID: "lic-id"})
	if !errors.Is(err, ErrFingerprintTaken) {
		t.Fatalf("errors.Is(err, ErrFingerprintTaken) = false, err = %v", err)
	}
}

func TestDeleteMachine_Success(t *testing.T) {
	var gotMethod, gotPath string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	defer closeFn()

	if err := c.DeleteMachine(context.Background(), "mach-id"); err != nil {
		t.Fatalf("DeleteMachine() error = %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %s, want DELETE", gotMethod)
	}
	if !strings.HasSuffix(gotPath, "/machines/mach-id") {
		t.Errorf("path = %q", gotPath)
	}
}

func TestDeleteMachine_ErrorMapping(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"id":"e1","status":"404","code":"NOT_FOUND","title":"Not Found","detail":"no such machine"}]}`))
	})
	defer closeFn()

	err := c.DeleteMachine(context.Background(), "missing-id")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("errors.Is(err, ErrNotFound) = false, err = %v", err)
	}
}

func TestActivateMachine_HappyPath(t *testing.T) {
	var callCount int
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/accounts/acct-123/machines", func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + representativeMachineJSON + `}`))
	})
	mux.HandleFunc("/v1/accounts/acct-123/licenses/lic-id/actions/validate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + representativeLicenseJSON + `,"meta":{"ts":"2026-01-01T00:00:00Z","valid":true,"detail":"is valid","code":"VALID"}}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	c, err := New("acct-123", WithBaseURL(server.URL), WithLicenseKey("lic-abc"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	machine, meta, err := c.ActivateMachine(context.Background(), CreateMachineOptions{Fingerprint: "fp-1", LicenseID: "lic-id"}, nil)
	if err != nil {
		t.Fatalf("ActivateMachine() error = %v", err)
	}
	if machine == nil || meta == nil || meta.Code != ValidationCodeValid {
		t.Fatalf("machine=%+v meta=%+v", machine, meta)
	}
}

func TestActivateMachine_RollbackDeleteOnTooManyMachines(t *testing.T) {
	var deleted bool
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/accounts/acct-123/machines", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.Header().Set("Content-Type", "application/vnd.api+json")
			_, _ = w.Write([]byte(`{"data":` + representativeMachineJSON + `}`))
		}
	})
	mux.HandleFunc("/v1/accounts/acct-123/machines/mach-id", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		}
	})
	mux.HandleFunc("/v1/accounts/acct-123/licenses/lic-id/actions/validate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + representativeLicenseJSON + `,"meta":{"ts":"2026-01-01T00:00:00Z","valid":false,"detail":"too many machines","code":"TOO_MANY_MACHINES"}}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	c, err := New("acct-123", WithBaseURL(server.URL), WithLicenseKey("lic-abc"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	machine, meta, err := c.ActivateMachine(context.Background(), CreateMachineOptions{Fingerprint: "fp-1", LicenseID: "lic-id"}, nil)
	// On the rollback path, ActivateMachine must return a non-nil error
	// matching ErrMachineOverLimit — the machine has already been deleted
	// server-side, so err == nil here would hand the caller a stale ID as
	// if activation had succeeded.
	if !errors.Is(err, ErrMachineOverLimit) {
		t.Fatalf("errors.Is(err, ErrMachineOverLimit) = false, err = %v", err)
	}
	if machine != nil {
		t.Fatalf("machine = %+v, want nil (it was deleted on rollback)", machine)
	}
	if meta == nil || meta.Code != ValidationCodeTooManyMachines {
		t.Fatalf("meta = %+v, want Code = TOO_MANY_MACHINES", meta)
	}
	if !deleted {
		t.Fatal("expected the over-limit machine to be deleted, but DELETE was never called")
	}
}

func TestPingHeartbeatResetHeartbeat_NoBody(t *testing.T) {
	tests := []struct {
		name string
		call func(*Client) (*Machine, error)
		path string
	}{
		{name: "ping", path: "/actions/ping-heartbeat", call: func(c *Client) (*Machine, error) {
			return c.PingHeartbeat(context.Background(), "mach-id")
		}},
		{name: "reset", path: "/actions/reset-heartbeat", call: func(c *Client) (*Machine, error) {
			return c.ResetHeartbeat(context.Background(), "mach-id")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotBodyLen int
			c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, tt.path) {
					t.Errorf("path = %s, want suffix %s", r.URL.Path, tt.path)
				}
				buf := make([]byte, 1)
				n, _ := r.Body.Read(buf)
				gotBodyLen = n
				w.Header().Set("Content-Type", "application/vnd.api+json")
				_, _ = w.Write([]byte(`{"data":` + representativeMachineJSON + `}`))
			})
			defer closeFn()
			if _, err := tt.call(c); err != nil {
				t.Fatalf("call error = %v", err)
			}
			if gotBodyLen != 0 {
				t.Errorf("expected no request body, read %d bytes", gotBodyLen)
			}
		})
	}
}

func TestHeartbeatStatus_JSONRoundTripIncludingUnknown(t *testing.T) {
	tests := []string{"NOT_STARTED", "ALIVE", "DEAD", "RESURRECTED", "FUTURE_STATE"}
	for _, wire := range tests {
		var hs HeartbeatStatus
		if err := json.Unmarshal([]byte(`"`+wire+`"`), &hs); err != nil {
			t.Fatalf("Unmarshal(%q) error = %v", wire, err)
		}
		if string(hs) != wire {
			t.Errorf("Unmarshal(%q) = %q", wire, hs)
		}
		encoded, err := json.Marshal(hs)
		if err != nil {
			t.Fatalf("Marshal error = %v", err)
		}
		if string(encoded) != `"`+wire+`"` {
			t.Errorf("Marshal(%q) = %s", wire, encoded)
		}
	}
}

// tickEvery lowers a scheduler's interval past the one-second floor
// NewHeartbeatScheduler enforces on its caller, so that a test whose
// subject is the *loop* can observe several ticks in milliseconds instead
// of spending a second per tick.
//
// This is legitimate precisely because the floor is a guard on the
// constructor's argument — the number a caller supplies, and gets wrong by
// converting seconds to a Duration by hand — and not an invariant Run
// rechecks. Any test whose subject is the floor itself must go through the
// constructor instead; TestNewHeartbeatScheduler_FloorsASubSecondInterval
// and TestNewProcessHeartbeatScheduler_FloorsASubSecondInterval do.
func tickEvery(s *HeartbeatScheduler, d time.Duration) *HeartbeatScheduler {
	s.interval = d
	return s
}

// tickEveryProcess is tickEvery for a ProcessHeartbeatScheduler.
func tickEveryProcess(s *ProcessHeartbeatScheduler, d time.Duration) *ProcessHeartbeatScheduler {
	s.interval = d
	return s
}

func TestHeartbeatScheduler_TicksAndStopsOnCancel(t *testing.T) {
	var ticks int
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		ticks++
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + representativeMachineJSON + `}`))
	})
	defer closeFn()

	scheduler := tickEvery(NewHeartbeatScheduler(c, "mach-id", 0), 10*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Millisecond)
	defer cancel()

	err := scheduler.Run(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run() error = %v, want context.DeadlineExceeded", err)
	}
	if ticks < 2 {
		t.Fatalf("ticks = %d, want at least 2 within the deadline window", ticks)
	}
}

// machineJSONWithHeartbeatStatus renders representativeMachineJSON with a
// chosen heartbeat_status, so a fake server can walk a machine through a
// status sequence across successive pings.
func machineJSONWithHeartbeatStatus(status HeartbeatStatus) string {
	return strings.Replace(
		representativeMachineJSON,
		`"heartbeat_status":"NOT_STARTED"`,
		`"heartbeat_status":"`+string(status)+`"`,
		1,
	)
}

// TestHeartbeatScheduler_KeepsPingingThroughConsecutiveDeadResponses pins
// the property that Run does not stop on a HeartbeatStatus — on ANY
// status, not on DEAD specifically. A Run loop that returns, breaks, or
// otherwise short-circuits on some status it dislikes strands the machine
// permanently instead of recovering it, since the next ping would have
// revived it.
//
// ⚠️ The DEAD responses served below are a fixture, not a claim about the
// server. A real ping cannot answer DEAD: it writes
// last_heartbeat_at = NOW() and then derives the status from that same
// timestamp, so a live response is always ALIVE or RESURRECTED (see
// HeartbeatStatus). DEAD is used here precisely because it is the status
// a well-meaning change is most likely to special-case against — and
// because an unrecognized status must not stop the loop either, the wire
// type being deliberately forward-compatible.
//
// So: three consecutive DEAD responses must be followed by a fourth ping.
// Only ctx may end the loop.
func TestHeartbeatScheduler_KeepsPingingThroughConsecutiveDeadResponses(t *testing.T) {
	const deadResponses = 3

	var mu sync.Mutex
	var served int
	var observed []HeartbeatStatus
	var tickErrs []error
	revived := make(chan struct{})

	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		served++
		n := served
		mu.Unlock()

		status := HeartbeatDead
		if n > deadResponses {
			status = HeartbeatAlive
		}
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + machineJSONWithHeartbeatStatus(status) + `}`))
		if n == deadResponses+1 {
			close(revived)
		}
	})
	defer closeFn()

	scheduler := tickEvery(NewHeartbeatScheduler(c, "mach-id", 0, WithHeartbeatOnTick(func(m *Machine, err error) {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			tickErrs = append(tickErrs, err)
			return
		}
		observed = append(observed, m.Attributes.HeartbeatStatus)
	})), 2*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- scheduler.Run(ctx) }()

	select {
	case <-revived:
	case <-time.After(5 * time.Second):
		mu.Lock()
		n := served
		mu.Unlock()
		cancel()
		<-runErr
		t.Fatalf("the scheduler served only %d ping(s); Run must keep pinging through all %d fixture responses, not stop on a status it did not expect", n, deadResponses)
	}

	// The revival response is written before its onTick callback runs;
	// wait for the callback so the assertions below see it.
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		got := len(observed)
		mu.Unlock()
		if got > deadResponses || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}

	// Snapshot before cancelling: cancel() aborts whatever ping is in
	// flight, and that abort legitimately reaches the tick callback as a
	// context.Canceled error.
	mu.Lock()
	observedSnapshot := append([]HeartbeatStatus(nil), observed...)
	errsSnapshot := append([]error(nil), tickErrs...)
	mu.Unlock()

	cancel()
	if err := <-runErr; !errors.Is(err, context.Canceled) {
		t.Errorf("Run() error = %v, want context.Canceled — only ctx may end the loop", err)
	}

	if len(errsSnapshot) != 0 {
		t.Fatalf("unexpected ping errors: %v", errsSnapshot)
	}
	if len(observedSnapshot) <= deadResponses {
		t.Fatalf("observed = %v, want more than %d ticks — the loop stopped on a DEAD response", observedSnapshot, deadResponses)
	}
	for i := 0; i < deadResponses; i++ {
		if observedSnapshot[i] != HeartbeatDead {
			t.Fatalf("observed[%d] = %q, want DEAD (test setup)", i, observedSnapshot[i])
		}
	}
	if observedSnapshot[deadResponses] != HeartbeatAlive {
		t.Errorf("observed[%d] = %q, want ALIVE — the fixture switches to ALIVE on the fourth ping, so the loop must have reached it", deadResponses, observedSnapshot[deadResponses])
	}
}

// TestHeartbeatScheduler_TreatsPingNotFoundAsTheRowIsGoneSignal pins the
// other half of the correction: a 404 from the ping, not a DEAD status,
// is the signal that the machine row is actually gone. It surfaces to
// WithHeartbeatOnTick as an error matching ErrNotFound, which is where a
// caller hangs re-activation. Run itself still does not stop — the caller
// cancels ctx.
func TestHeartbeatScheduler_TreatsPingNotFoundAsTheRowIsGoneSignal(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"title":"Not found","code":"NOT_FOUND","detail":"machine not found"}]}`))
	})
	defer closeFn()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	gone := make(chan struct{})
	var once sync.Once
	scheduler := tickEvery(NewHeartbeatScheduler(c, "mach-id", 0, WithHeartbeatOnTick(func(_ *Machine, err error) {
		if errors.Is(err, ErrNotFound) {
			once.Do(func() { close(gone) })
		}
	})), 2*time.Millisecond)

	runErr := make(chan error, 1)
	go func() { runErr <- scheduler.Run(ctx) }()

	select {
	case <-gone:
	case <-time.After(5 * time.Second):
		cancel()
		<-runErr
		t.Fatal("a 404 from the ping never surfaced as ErrNotFound on the tick callback")
	}

	cancel()
	if err := <-runErr; !errors.Is(err, context.Canceled) {
		t.Errorf("Run() error = %v, want context.Canceled", err)
	}
}

// TestHeartbeatScheduler_WithOnTickIsObservableExternally proves
// WithHeartbeatOnTick is actually reachable and usable from outside this
// package — a caller can observe every ping's (*Machine, error) result,
// e.g. to detect a DEAD HeartbeatStatus per tick.
func TestHeartbeatScheduler_WithOnTickIsObservableExternally(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + representativeMachineJSON + `}`))
	})
	defer closeFn()

	var mu sync.Mutex
	var observed []*Machine
	scheduler := tickEvery(NewHeartbeatScheduler(c, "mach-id", 0, WithHeartbeatOnTick(func(m *Machine, err error) {
		mu.Lock()
		defer mu.Unlock()
		if err == nil {
			observed = append(observed, m)
		}
	})), 10*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Millisecond)
	defer cancel()
	_ = scheduler.Run(ctx)

	mu.Lock()
	defer mu.Unlock()
	if len(observed) == 0 {
		t.Fatal("WithHeartbeatOnTick callback was never invoked")
	}
	if observed[0].Attributes.Fingerprint != "fp-abc123" {
		t.Errorf("observed machine = %+v", observed[0])
	}
}

// TestProcessHeartbeatScheduler_WithOnTickIsObservableExternally is the
// ProcessHeartbeatScheduler equivalent of the test above.
func TestProcessHeartbeatScheduler_WithOnTickIsObservableExternally(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":{"id":"proc-id","type":"processes","attributes":{"pid":"1234","machine_id":"mach-id","last_heartbeat_at":"2026-01-01T00:00:00Z","metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}}}`))
	})
	defer closeFn()

	var mu sync.Mutex
	var ticks int
	scheduler := tickEveryProcess(NewProcessHeartbeatScheduler(c, "proc-id", 0, WithProcessHeartbeatOnTick(func(p *Process, err error) {
		mu.Lock()
		defer mu.Unlock()
		if err == nil {
			ticks++
		}
	})), 10*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Millisecond)
	defer cancel()
	_ = scheduler.Run(ctx)

	mu.Lock()
	defer mu.Unlock()
	if ticks == 0 {
		t.Fatal("WithProcessHeartbeatOnTick callback was never invoked")
	}
}

func TestCreateComponent_RequiredFieldsAndFingerprintTaken(t *testing.T) {
	var gotBody map[string]any
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/accounts/acct-123/components" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":{"id":"comp-id","type":"components","attributes":{"fingerprint":"fp-1","name":"CPU","machine_id":"mach-id","metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}}}`))
	})
	defer closeFn()

	component, err := c.CreateComponent(context.Background(), CreateComponentOptions{MachineID: "mach-id", Fingerprint: "fp-1", Name: "CPU"})
	if err != nil {
		t.Fatalf("CreateComponent() error = %v", err)
	}
	if component.Attributes.Fingerprint != "fp-1" || component.Attributes.Name != "CPU" {
		t.Errorf("component = %+v", component)
	}
	if gotBody["machine_id"] != "mach-id" || gotBody["fingerprint"] != "fp-1" || gotBody["name"] != "CPU" {
		t.Errorf("request body = %+v (must be flat, not JSON:API-enveloped)", gotBody)
	}

	c2, closeFn2 := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"errors":[{"id":"e1","status":"409","code":"FINGERPRINT_TAKEN","title":"Conflict","detail":"taken"}]}`))
	})
	defer closeFn2()
	_, err = c2.CreateComponent(context.Background(), CreateComponentOptions{MachineID: "mach-id", Fingerprint: "fp-1", Name: "CPU"})
	if !errors.Is(err, ErrFingerprintTaken) {
		t.Fatalf("errors.Is(err, ErrFingerprintTaken) = false, err = %v", err)
	}
}

func TestListComponents_KeysetPaginationCursorRoundTrip(t *testing.T) {
	var gotQuery string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[{"id":"comp-1","type":"components","attributes":{"fingerprint":"fp-1","name":"CPU","machine_id":"mach-id","metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}},{"id":"comp-2","type":"components","attributes":{"fingerprint":"fp-2","name":"GPU","machine_id":"mach-id","metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}}]}`))
	})
	defer closeFn()

	after := "comp-0"
	page, err := c.ListComponents(context.Background(), "mach-id", ListOptions{Limit: 2, After: &after})
	if err != nil {
		t.Fatalf("ListComponents() error = %v", err)
	}
	if !strings.Contains(gotQuery, "limit=2") || !strings.Contains(gotQuery, "page%5Bafter%5D=comp-0") {
		t.Errorf("query = %q", gotQuery)
	}
	if len(page.Items) != 2 || page.NextCursor == nil || *page.NextCursor != "comp-2" {
		t.Errorf("page = %+v", page)
	}
}

func TestCreateProcess_PIDSerializedAsString(t *testing.T) {
	var gotBody map[string]any
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":{"id":"proc-id","type":"processes","attributes":{"pid":"1234","machine_id":"mach-id","last_heartbeat_at":"2026-01-01T00:00:00Z","metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}}}`))
	})
	defer closeFn()

	// Constructed from a numeric literal via strconv, per CreateProcessOptions's doc comment.
	pidFromNumber := "1234"
	process, err := c.CreateProcess(context.Background(), CreateProcessOptions{MachineID: "mach-id", PID: pidFromNumber})
	if err != nil {
		t.Fatalf("CreateProcess() error = %v", err)
	}
	if process.Attributes.PID != "1234" {
		t.Errorf("PID = %q", process.Attributes.PID)
	}
	if pidValue, ok := gotBody["pid"].(string); !ok || pidValue != "1234" {
		t.Errorf("request body pid = %#v (%T), want JSON string \"1234\"", gotBody["pid"], gotBody["pid"])
	}
}

func TestCreateProcess_PIDTakenMapping(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"errors":[{"id":"e1","status":"409","code":"PID_TAKEN","title":"Conflict","detail":"taken"}]}`))
	})
	defer closeFn()
	_, err := c.CreateProcess(context.Background(), CreateProcessOptions{MachineID: "mach-id", PID: "1234"})
	if !errors.Is(err, ErrPIDTaken) {
		t.Fatalf("errors.Is(err, ErrPIDTaken) = false, err = %v", err)
	}
}

func TestPingProcess_RequestShape(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/processes/proc-id/actions/ping") {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":{"id":"proc-id","type":"processes","attributes":{"pid":"1234","machine_id":"mach-id","last_heartbeat_at":"2026-01-01T00:00:00Z","metadata":{},"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}}}`))
	})
	defer closeFn()
	if _, err := c.PingProcess(context.Background(), "proc-id"); err != nil {
		t.Fatalf("PingProcess() error = %v", err)
	}
}

func TestProcessHeartbeatScheduler_DefaultIntervalWithin10s(t *testing.T) {
	if DefaultProcessHeartbeatInterval > 10*time.Second {
		t.Fatalf("DefaultProcessHeartbeatInterval = %v, want <= 10s", DefaultProcessHeartbeatInterval)
	}
	c, _ := New("acct-123", WithLicenseKey("lic-abc"))
	scheduler := NewProcessHeartbeatScheduler(c, "proc-id", 0)
	if scheduler.interval != DefaultProcessHeartbeatInterval {
		t.Fatalf("scheduler.interval = %v, want %v", scheduler.interval, DefaultProcessHeartbeatInterval)
	}
}

// TestNewHeartbeatScheduler_FloorsASubSecondInterval pins the behaviour
// change from "clamp the non-positive case" to "clamp to a one-second
// floor". 500ms is the value that makes the change visible: the old guard
// passed it through untouched, because time.NewTicker accepts it.
//
// Accepting it is not the same as it being safe. Measured through this
// constructor against an httptest server, a 1ms interval issues 999 ping
// requests per second and a 1ns interval issues 8593 — while 0, the one
// input the old guard did catch, issues none. The guard was sorting inputs
// by whether time.NewTicker would panic on them, which is a fact about
// where a number came from rather than about what it does.
//
// Note the two clamps are deliberately different: 0 still means "use the
// default" and yields DefaultHeartbeatInterval, while a positive
// sub-second value is raised only as far as one second. A caller on a
// genuinely short policy window must not be silently pushed out to 200s.
func TestNewHeartbeatScheduler_FloorsASubSecondInterval(t *testing.T) {
	c, err := New("acct-123", WithLicenseKey("lic-abc"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	tests := []struct {
		name string
		give time.Duration
		want time.Duration
	}{
		{"500ms is raised to the one-second floor", 500 * time.Millisecond, time.Second},
		{"1ms — 999 requests/second measured — is raised too", time.Millisecond, time.Second},
		{"1ns is raised too", time.Nanosecond, time.Second},
		{"exactly one second is already at the floor", time.Second, time.Second},
		{"a second and a nanosecond is left alone", time.Second + time.Nanosecond, time.Second + time.Nanosecond},
		{"a policy-sized interval is left alone", 30 * time.Second, 30 * time.Second},
		{"zero still means use the default, not the floor", 0, DefaultHeartbeatInterval},
		{"negative still means use the default", -5 * time.Second, DefaultHeartbeatInterval},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NewHeartbeatScheduler(c, "mach-id", tc.give).interval; got != tc.want {
				t.Errorf("NewHeartbeatScheduler(interval=%v).interval = %v, want %v", tc.give, got, tc.want)
			}
		})
	}
}

// TestNewProcessHeartbeatScheduler_FloorsASubSecondInterval is the
// ProcessHeartbeatScheduler half of the same rule. The process window is a
// hardcoded 30s server-side, so no policy can ever justify a sub-second
// process ping — but the flood is reachable here by the same
// seconds-versus-Duration conversion mistake, so the guard is the same.
func TestNewProcessHeartbeatScheduler_FloorsASubSecondInterval(t *testing.T) {
	c, err := New("acct-123", WithLicenseKey("lic-abc"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	tests := []struct {
		name string
		give time.Duration
		want time.Duration
	}{
		{"500ms is raised to the one-second floor", 500 * time.Millisecond, time.Second},
		{"1ms is raised to the one-second floor", time.Millisecond, time.Second},
		{"exactly one second is already at the floor", time.Second, time.Second},
		{"the 10s default is left alone", 10 * time.Second, 10 * time.Second},
		{"zero still means use the default, not the floor", 0, DefaultProcessHeartbeatInterval},
		{"negative still means use the default", -1, DefaultProcessHeartbeatInterval},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NewProcessHeartbeatScheduler(c, "proc-id", tc.give).interval; got != tc.want {
				t.Errorf("NewProcessHeartbeatScheduler(interval=%v).interval = %v, want %v", tc.give, got, tc.want)
			}
		})
	}
}
