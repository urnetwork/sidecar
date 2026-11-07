package mxedgeservice_test

import (
	"errors"
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

// Settings that pass Validate. The readiness probe is parked far off, so only a test about it moves
// it, and timers a test counts stay still.
func testSettings() *mxedgeservice.MxEdgeSettings {
	settings := mxedgeservice.DefaultMxEdgeSettings()
	settings.BannerHostName = testBannerHostName
	settings.DeviationUrl = testDeviationUrl
	settings.ReadyProbeInterval = 1000 * time.Hour
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
`))
	if err != nil {
		t.Fatal(err)
	}
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
	}
	if *settings != *want {
		t.Errorf("loaded %+v, want %+v", settings, want)
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
	if *settings != *want {
		t.Errorf("loaded %+v, want %+v", settings, want)
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
		{name: "a memory past one UTC day", document: testRequiredSettings + "closed_handshake_ttl: 24h1s\n"},
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

func TestValidateTakesAMemoryOfExactlyOneDay(t *testing.T) {
	settings := testSettings()
	settings.ClosedHandshakeTtl = 24 * time.Hour
	if err := settings.Validate(); err != nil {
		t.Error(err)
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
		"sender_sessions":           func(settings *mxedgeservice.MxEdgeSettings) { settings.SenderSessionCount = 0 },
		"sender_aggregate_sessions": func(settings *mxedgeservice.MxEdgeSettings) { settings.SenderAggregateSessionCount = 0 },
		"network_sender_sessions":   func(settings *mxedgeservice.MxEdgeSettings) { settings.NetworkSenderSessionCount = 0 },
		"network_sessions":          func(settings *mxedgeservice.MxEdgeSettings) { settings.NetworkSessionCount = 0 },
		"max_connections":           func(settings *mxedgeservice.MxEdgeSettings) { settings.ProcessSessionCount = 0 },
		"dialog_timeout":            func(settings *mxedgeservice.MxEdgeSettings) { settings.DialogTimeout = 0 },
		"starttls_quiet":            func(settings *mxedgeservice.MxEdgeSettings) { settings.StartTlsQuietTimeout = 0 },
		"client_hello_timeout":      func(settings *mxedgeservice.MxEdgeSettings) { settings.ClientHelloTimeout = 0 },
		"client_hello_max_bytes":    func(settings *mxedgeservice.MxEdgeSettings) { settings.ClientHelloByteCount = 0 },
		"closed_handshake_ttl":      func(settings *mxedgeservice.MxEdgeSettings) { settings.ClosedHandshakeTtl = 0 },
		"store_timeout":             func(settings *mxedgeservice.MxEdgeSettings) { settings.StoreTimeout = 0 },
		"ready_probe_interval":      func(settings *mxedgeservice.MxEdgeSettings) { settings.ReadyProbeInterval = 0 },
		"accept_retry_delay":        func(settings *mxedgeservice.MxEdgeSettings) { settings.AcceptRetryDelay = 0 },
		"drain_timeout":             func(settings *mxedgeservice.MxEdgeSettings) { settings.DrainTimeout = 0 },
	} {
		settings := testSettings()
		clear(settings)
		err := settings.Validate()
		if !errors.Is(err, mxedgeservice.ErrMxEdgeSettingsRefused) || !strings.Contains(err.Error(), key) {
			t.Errorf("%s at zero: %v", key, err)
		}
	}
}
