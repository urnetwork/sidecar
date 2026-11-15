package mxedgeservice_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/mxedgeservice"
)

const (
	testBannerHostName = "mx.example"
	testDeviationUrl   = "https://deviation.example/rfc3207"
	// the two keys with no default, which a file must set
	testRequiredSettings = "banner_host: " + testBannerHostName + "\ndeviation_url: " + testDeviationUrl + "\n"
)

// Settings that pass Validate. The readiness probe and the session records' flush are parked far off,
// so only a test about one moves it, and timers a test counts stay still.
func testSettings() *mxedgeservice.MxEdgeSettings {
	settings := mxedgeservice.DefaultMxEdgeSettings()
	settings.BannerHostName = testBannerHostName
	settings.DeviationUrl = testDeviationUrl
	settings.ReadyProbeInterval = 1000 * time.Hour
	settings.RecordFlushInterval = 1000 * time.Hour
	return settings
}

func TestDefaultsHoldTheDesignsNumbers(t *testing.T) {
	settings := mxedgeservice.DefaultMxEdgeSettings()
	if settings.NetworkSenderSessionCount != 2 {
		t.Errorf("§15.4 fixes 2 sessions per sender /24 per network, not %d", settings.NetworkSenderSessionCount)
	}
	if settings.ClosedHandshakeTtl != time.Hour {
		t.Errorf("§15.4 remembers a closed handshake for 1 h, not %v", settings.ClosedHandshakeTtl)
	}
	if settings.RecordFlushInterval != 10*time.Second {
		t.Errorf("§15.4 writes session records in 10 s batches, not %v", settings.RecordFlushInterval)
	}
	if settings.SenderSessionCount != 8 || settings.SenderAggregateSessionCount != 32 || settings.NetworkSessionCount != 256 {
		t.Errorf("reading 2 proposes 8, 32 and 256, not %d, %d and %d",
			settings.SenderSessionCount, settings.SenderAggregateSessionCount, settings.NetworkSessionCount)
	}
}

// A default must not carry a production name, so a host that sets neither cannot start.
func TestDefaultsAloneDoNotValidate(t *testing.T) {
	settings := mxedgeservice.DefaultMxEdgeSettings()
	if settings.BannerHostName != "" || settings.DeviationUrl != "" {
		t.Errorf("defaults hold %q and %q", settings.BannerHostName, settings.DeviationUrl)
	}
	if err := settings.Validate(); !errors.Is(err, mxedgeservice.ErrMxEdgeSettingsRefused) {
		t.Errorf("validate said %v", err)
	}
}

func TestLoadTakesEveryKey(t *testing.T) {
	settings, err := mxedgeservice.LoadMxEdgeSettings([]byte(testRequiredSettings + `
sender_sessions: 3
sender_aggregate_sessions: 4
network_sender_sessions: 5
network_sessions: 6
max_connections: 7
dialog_timeout: 1m
starttls_quiet: 250ms
client_hello_timeout: 5s
client_hello_max_bytes: 8192
closed_handshake_ttl: 30m
store_timeout: 2s
ready_probe_interval: 30s
accept_retry_delay: 1500ms
drain_timeout: 2m
record_flush_interval: 20s
record_write_timeout: 3s
record_queue: 9
record_batch: 4
platform_report_host: rpt.example
platform_root: root.example
platform_abuse_url: https://abuse.example/form
platform_message_max_bytes: 1024
platform_buffer_max_bytes: 4096
platform_recipients: 3
platform_handshake_timeout: 7s
platform_idle_timeout: 2m
platform_session_timeout: 20m
route_root: root.example
route_cache_ttl: 3s
route_cache_entries: 11
clients: 2
find_timeout: 1s
find_max: 4
accept_ticket_timeout: 6s
accept_setup_timeout: 20s
alert_timeout: 3s
lease_timeout: 4s
splice_idle_timeout: 9m
splice_slow_timeout: 8m
splice_slow_bytes: 2048
splice_session_timeout: 25m
splice_message_multiple: 3
splice_extra_bytes: 4096
splice_buffer_bytes: 8192
cold_message_max_bytes: 1048576
limits_refresh_interval: 2m
limits_active_window: 20m
limits_networks: 12
ptr_timeout: 6s
ptr_names: 2
ptr_lookups: 13
`))
	if err != nil {
		t.Fatal(err)
	}
	defaults := mxedgeservice.DefaultMxEdgeSettings()
	want := &mxedgeservice.MxEdgeSettings{
		BannerHostName:              testBannerHostName,
		DeviationUrl:                testDeviationUrl,
		SenderSessionCount:          3,
		SenderAggregateSessionCount: 4,
		NetworkSenderSessionCount:   5,
		NetworkSessionCount:         6,
		ProcessSessionCount:         7,
		DialogTimeout:               time.Minute,
		StartTlsQuietTimeout:        250 * time.Millisecond,
		ClientHelloTimeout:          5 * time.Second,
		ClientHelloByteCount:        8192,
		ClosedHandshakeTtl:          30 * time.Minute,
		StoreTimeout:                2 * time.Second,
		ReadyProbeInterval:          30 * time.Second,
		AcceptRetryDelay:            1500 * time.Millisecond,
		DrainTimeout:                2 * time.Minute,
		RecordFlushInterval:         20 * time.Second,
		RecordWriteTimeout:          3 * time.Second,
		RecordQueueCount:            9,
		RecordBatchCount:            4,
		PlatformReportHostName:      "rpt.example",
		PlatformRootDomainName:      "root.example",
		PlatformAbuseUrl:            "https://abuse.example/form",
		PlatformMessageByteCount:    1024,
		PlatformBufferByteCount:     4096,
		PlatformRecipientCount:      3,
		PlatformHandshakeTimeout:    7 * time.Second,
		PlatformIdleTimeout:         2 * time.Minute,
		PlatformSessionTimeout:      20 * time.Minute,
		RouteRootDomainName:         "root.example",
		RouteCacheTtl:               3 * time.Second,
		RouteCacheEntryCount:        11,
		Clients:                     2,
		FindTimeout:                 time.Second,
		FindCount:                   4,
		AcceptTicketTimeout:         6 * time.Second,
		AcceptSetupTimeout:          20 * time.Second,
		AlertTimeout:                3 * time.Second,
		LeaseTimeout:                4 * time.Second,
		SpliceIdleTimeout:           9 * time.Minute,
		SpliceSlowTimeout:           8 * time.Minute,
		SpliceSlowByteCount:         2048,
		SpliceSessionTimeout:        25 * time.Minute,
		SpliceMessageMultiple:       3,
		SpliceExtraByteCount:        4096,
		SpliceBufferByteCount:       8192,
		ColdMessageByteCount:        1048576,
		LimitsRefreshInterval:       2 * time.Minute,
		LimitsActiveWindow:          20 * time.Minute,
		LimitsNetworkCount:          12,
		PtrTimeout:                  6 * time.Second,
		PtrNameCount:                2,
		PtrLookupCount:              13,
		Ingress:                     defaults.Ingress,
		Usage:                       defaults.Usage,
		HostNameMaxByteCount:        defaults.HostNameMaxByteCount,
		HostLabelMaxByteCount:       defaults.HostLabelMaxByteCount,
		ReplyUrlMaxByteCount:        defaults.ReplyUrlMaxByteCount,
	}
	if !reflect.DeepEqual(settings, want) {
		t.Errorf("loaded %+v, want %+v", settings, want)
	}
	if err := settings.ValidateRouter(); err != nil {
		t.Error(err)
	}
}

func TestLoadKeepsDefaultsForWhatAFileLeavesOut(t *testing.T) {
	settings, err := mxedgeservice.LoadMxEdgeSettings([]byte(testRequiredSettings))
	if err != nil {
		t.Fatal(err)
	}
	want := mxedgeservice.DefaultMxEdgeSettings()
	want.BannerHostName = testBannerHostName
	want.DeviationUrl = testDeviationUrl
	if !reflect.DeepEqual(settings, want) {
		t.Errorf("loaded %+v, want %+v", settings, want)
	}
	// the router's file must name its root
	if err := settings.ValidateRouter(); !errors.Is(err, mxedgeservice.ErrMxEdgeSettingsRefused) || !strings.Contains(err.Error(), "route_root") {
		t.Errorf("a router with no root: %v", err)
	}
}

func TestLoadRefuses(t *testing.T) {
	for _, c := range []struct {
		name     string
		document string
	}{
		{name: "an empty file", document: ""},
		{name: "no banner host", document: "deviation_url: " + testDeviationUrl + "\n"},
		{name: "no deviation url", document: "banner_host: " + testBannerHostName + "\n"},
		{name: "an unknown key", document: testRequiredSettings + "sender_session: 8\n"},
		{name: "a second document", document: testRequiredSettings + "---\nsender_sessions: 9\n"},
		{name: "a zero count", document: testRequiredSettings + "sender_sessions: 0\n"},
		{name: "a negative count", document: testRequiredSettings + "network_sessions: -1\n"},
		{name: "a count as a word", document: testRequiredSettings + "sender_sessions: many\n"},
		// yaml.v3 truncates a float into an int, so 0.5 reads as zero, and 1.5 as 1
		{name: "a fraction under one", document: testRequiredSettings + "sender_sessions: 0.5\n"},
		{name: "a zero duration", document: testRequiredSettings + "dialog_timeout: 0s\n"},
		{name: "a negative duration", document: testRequiredSettings + "drain_timeout: -5s\n"},
		{name: "a duration with no unit", document: testRequiredSettings + "drain_timeout: 600\n"},
		{name: "a memory that outlives its daily key", document: testRequiredSettings + "closed_handshake_ttl: 1h1s\n"},
		{name: "a host with a space", document: "banner_host: mx example\ndeviation_url: " + testDeviationUrl + "\n"},
		{name: "a host with a line break", document: "banner_host: \"mx.example\\r\\n250 fake\"\ndeviation_url: " + testDeviationUrl + "\n"},
		{name: "a host with an empty label", document: "banner_host: mx..example\ndeviation_url: " + testDeviationUrl + "\n"},
		{name: "a host with a leading hyphen", document: "banner_host: -mx.example\ndeviation_url: " + testDeviationUrl + "\n"},
		{name: "a host with a trailing hyphen", document: "banner_host: mx-.example\ndeviation_url: " + testDeviationUrl + "\n"},
		{name: "a host label too long", document: "banner_host: " + strings.Repeat("a", 64) + ".example\ndeviation_url: " + testDeviationUrl + "\n"},
		{name: "a host of 254 bytes", document: "banner_host: " + strings.Repeat("a.", 123) + "examplex\ndeviation_url: " + testDeviationUrl + "\n"},
		{name: "a url over http", document: "banner_host: mx.example\ndeviation_url: http://deviation.example/rfc3207\n"},
		{name: "a url with no host", document: "banner_host: mx.example\ndeviation_url: https:///rfc3207\n"},
		{name: "a url with a line break", document: "banner_host: mx.example\ndeviation_url: \"https://deviation.example/\\r\\n550 fake\"\n"},
		{name: "a relative url", document: "banner_host: mx.example\ndeviation_url: /rfc3207\n"},
		{name: "a url with a space", document: "banner_host: mx.example\ndeviation_url: \"https://deviation.example/a b\"\n"},
		{name: "a url with a byte past ASCII", document: "banner_host: mx.example\ndeviation_url: \"https://deviation.example/\\xe9\"\n"},
		{name: "a url too long for a reply", document: "banner_host: mx.example\ndeviation_url: https://deviation.example/" + strings.Repeat("a", 400) + "\n"},
	} {
		if _, err := mxedgeservice.LoadMxEdgeSettings([]byte(c.document)); !errors.Is(err, mxedgeservice.ErrMxEdgeSettingsRefused) {
			t.Errorf("%s: loaded with %v", c.name, err)
		}
	}
}

func TestValidateRefusesNoSettings(t *testing.T) {
	var settings *mxedgeservice.MxEdgeSettings
	if err := settings.Validate(); !errors.Is(err, mxedgeservice.ErrMxEdgeSettingsRefused) {
		t.Errorf("validate said %v", err)
	}
}

// A refusal may reach a log, so Validate says where the fault is and never what the value was.
func TestValidateNamesTheKeyAndNotItsValue(t *testing.T) {
	settings := testSettings()
	settings.DeviationUrl = "http://private.example/a"
	err := settings.Validate()
	if err == nil {
		t.Fatal("validated")
	}
	if text := err.Error(); !strings.Contains(text, "deviation_url") || strings.Contains(text, "private.example") {
		t.Errorf("the refusal reads %s", text)
	}
}

// k lives 25 h from a creation that may come at its day's first moment, so an hour is the most an
// entry under it can live and still be read.
func TestValidateTakesAMemoryOfExactlyAnHourAndNoMore(t *testing.T) {
	settings := testSettings()
	settings.ClosedHandshakeTtl = time.Hour
	if err := settings.Validate(); err != nil {
		t.Error(err)
	}
	settings.ClosedHandshakeTtl = time.Hour + time.Nanosecond
	if err := settings.Validate(); !errors.Is(err, mxedgeservice.ErrMxEdgeSettingsRefused) {
		t.Errorf("validate said %v", err)
	}
	if mxedgeservice.DailyKeyTtl != 25*time.Hour {
		t.Errorf("k lives %v, not the resolution's EX 90000", mxedgeservice.DailyKeyTtl)
	}
}

func TestValidateTakesAHostAtItsLimits(t *testing.T) {
	for _, hostName := range []string{
		strings.Repeat("a", 63) + ".example",
		strings.Repeat("a.", 123) + "example",
		"MX-1.Example",
	} {
		settings := testSettings()
		settings.BannerHostName = hostName
		if err := settings.Validate(); err != nil {
			t.Errorf("%s: %v", hostName, err)
		}
	}
}

// Each number, named by its yaml key, so a new field cannot miss the rule.
func TestValidateRefusesEveryNumberAtZero(t *testing.T) {
	for key, clear := range map[string]func(settings *mxedgeservice.MxEdgeSettings){
		"sender_sessions":            func(settings *mxedgeservice.MxEdgeSettings) { settings.SenderSessionCount = 0 },
		"sender_aggregate_sessions":  func(settings *mxedgeservice.MxEdgeSettings) { settings.SenderAggregateSessionCount = 0 },
		"network_sender_sessions":    func(settings *mxedgeservice.MxEdgeSettings) { settings.NetworkSenderSessionCount = 0 },
		"network_sessions":           func(settings *mxedgeservice.MxEdgeSettings) { settings.NetworkSessionCount = 0 },
		"max_connections":            func(settings *mxedgeservice.MxEdgeSettings) { settings.ProcessSessionCount = 0 },
		"dialog_timeout":             func(settings *mxedgeservice.MxEdgeSettings) { settings.DialogTimeout = 0 },
		"starttls_quiet":             func(settings *mxedgeservice.MxEdgeSettings) { settings.StartTlsQuietTimeout = 0 },
		"client_hello_timeout":       func(settings *mxedgeservice.MxEdgeSettings) { settings.ClientHelloTimeout = 0 },
		"client_hello_max_bytes":     func(settings *mxedgeservice.MxEdgeSettings) { settings.ClientHelloByteCount = 0 },
		"closed_handshake_ttl":       func(settings *mxedgeservice.MxEdgeSettings) { settings.ClosedHandshakeTtl = 0 },
		"store_timeout":              func(settings *mxedgeservice.MxEdgeSettings) { settings.StoreTimeout = 0 },
		"ready_probe_interval":       func(settings *mxedgeservice.MxEdgeSettings) { settings.ReadyProbeInterval = 0 },
		"accept_retry_delay":         func(settings *mxedgeservice.MxEdgeSettings) { settings.AcceptRetryDelay = 0 },
		"drain_timeout":              func(settings *mxedgeservice.MxEdgeSettings) { settings.DrainTimeout = 0 },
		"record_flush_interval":      func(settings *mxedgeservice.MxEdgeSettings) { settings.RecordFlushInterval = 0 },
		"record_write_timeout":       func(settings *mxedgeservice.MxEdgeSettings) { settings.RecordWriteTimeout = 0 },
		"record_queue":               func(settings *mxedgeservice.MxEdgeSettings) { settings.RecordQueueCount = 0 },
		"record_batch":               func(settings *mxedgeservice.MxEdgeSettings) { settings.RecordBatchCount = 0 },
		"platform_message_max_bytes": func(settings *mxedgeservice.MxEdgeSettings) { settings.PlatformMessageByteCount = 0 },
		"platform_buffer_max_bytes":  func(settings *mxedgeservice.MxEdgeSettings) { settings.PlatformBufferByteCount = 0 },
		"platform_recipients":        func(settings *mxedgeservice.MxEdgeSettings) { settings.PlatformRecipientCount = 0 },
		"platform_handshake_timeout": func(settings *mxedgeservice.MxEdgeSettings) { settings.PlatformHandshakeTimeout = 0 },
		"platform_idle_timeout":      func(settings *mxedgeservice.MxEdgeSettings) { settings.PlatformIdleTimeout = 0 },
		"platform_session_timeout":   func(settings *mxedgeservice.MxEdgeSettings) { settings.PlatformSessionTimeout = 0 },
		"route_cache_ttl":            func(settings *mxedgeservice.MxEdgeSettings) { settings.RouteCacheTtl = 0 },
		"route_cache_entries":        func(settings *mxedgeservice.MxEdgeSettings) { settings.RouteCacheEntryCount = 0 },
		"clients":                    func(settings *mxedgeservice.MxEdgeSettings) { settings.Clients = 0 },
		"find_timeout":               func(settings *mxedgeservice.MxEdgeSettings) { settings.FindTimeout = 0 },
		"find_max":                   func(settings *mxedgeservice.MxEdgeSettings) { settings.FindCount = 0 },
		"accept_ticket_timeout":      func(settings *mxedgeservice.MxEdgeSettings) { settings.AcceptTicketTimeout = 0 },
		"accept_setup_timeout":       func(settings *mxedgeservice.MxEdgeSettings) { settings.AcceptSetupTimeout = 0 },
		"alert_timeout":              func(settings *mxedgeservice.MxEdgeSettings) { settings.AlertTimeout = 0 },
		"lease_timeout":              func(settings *mxedgeservice.MxEdgeSettings) { settings.LeaseTimeout = 0 },
		"splice_idle_timeout":        func(settings *mxedgeservice.MxEdgeSettings) { settings.SpliceIdleTimeout = 0 },
		"splice_slow_timeout":        func(settings *mxedgeservice.MxEdgeSettings) { settings.SpliceSlowTimeout = 0 },
		"splice_slow_bytes":          func(settings *mxedgeservice.MxEdgeSettings) { settings.SpliceSlowByteCount = 0 },
		"splice_session_timeout":     func(settings *mxedgeservice.MxEdgeSettings) { settings.SpliceSessionTimeout = 0 },
		"splice_message_multiple":    func(settings *mxedgeservice.MxEdgeSettings) { settings.SpliceMessageMultiple = 0 },
		"splice_extra_bytes":         func(settings *mxedgeservice.MxEdgeSettings) { settings.SpliceExtraByteCount = 0 },
		"splice_buffer_bytes":        func(settings *mxedgeservice.MxEdgeSettings) { settings.SpliceBufferByteCount = 0 },
		"cold_message_max_bytes":     func(settings *mxedgeservice.MxEdgeSettings) { settings.ColdMessageByteCount = 0 },
		"limits_refresh_interval":    func(settings *mxedgeservice.MxEdgeSettings) { settings.LimitsRefreshInterval = 0 },
		"limits_active_window":       func(settings *mxedgeservice.MxEdgeSettings) { settings.LimitsActiveWindow = 0 },
		"limits_networks":            func(settings *mxedgeservice.MxEdgeSettings) { settings.LimitsNetworkCount = 0 },
		"ptr_timeout":                func(settings *mxedgeservice.MxEdgeSettings) { settings.PtrTimeout = 0 },
		"ptr_names":                  func(settings *mxedgeservice.MxEdgeSettings) { settings.PtrNameCount = 0 },
		"ptr_lookups":                func(settings *mxedgeservice.MxEdgeSettings) { settings.PtrLookupCount = 0 },
		"HostNameMaxByteCount":       func(settings *mxedgeservice.MxEdgeSettings) { settings.HostNameMaxByteCount = 0 },
		"HostLabelMaxByteCount":      func(settings *mxedgeservice.MxEdgeSettings) { settings.HostLabelMaxByteCount = 0 },
		"ReplyUrlMaxByteCount":       func(settings *mxedgeservice.MxEdgeSettings) { settings.ReplyUrlMaxByteCount = 0 },
	} {
		settings := testSettings()
		clear(settings)
		err := settings.Validate()
		if !errors.Is(err, mxedgeservice.ErrMxEdgeSettingsRefused) || !strings.Contains(err.Error(), key) {
			t.Errorf("%s at zero: %v", key, err)
		}
	}
}
