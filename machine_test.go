package tamga

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
	disk := int32(2048)

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

	_, meta, err := c.ActivateMachine(context.Background(), CreateMachineOptions{Fingerprint: "fp-1", LicenseID: "lic-id"}, nil)
	if err != nil {
		t.Fatalf("ActivateMachine() error = %v", err)
	}
	if meta.Code != ValidationCodeTooManyMachines {
		t.Fatalf("meta.Code = %v", meta.Code)
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

func TestHeartbeatScheduler_TicksAndStopsOnCancel(t *testing.T) {
	var ticks int
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		ticks++
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":` + representativeMachineJSON + `}`))
	})
	defer closeFn()

	scheduler := NewHeartbeatScheduler(c, "mach-id", 10*time.Millisecond)
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
