package sidecar

import (
	"reflect"
	"testing"
	"time"
)

func TestDefaultSidecarSettingsMatchDesign(t *testing.T) {
	settings := DefaultSidecarSettings()

	checks := []struct {
		name string
		got  any
		want any
	}{
		// §5.9, §18.4
		{"Instance", settings.Instance, "default"},
		{"AppVersion", settings.AppVersion, Version},
		{"MemoryBudgetByteCount", settings.MemoryBudgetByteCount, int64(128 * 1024 * 1024)},
		// §6.5's StreamData limit
		{"StreamChunkByteCount", settings.StreamChunkByteCount, 4000},
		{"Log", settings.Log, nil},
		// §5.4: sdk's schedule
		{"RefreshWindowStart", settings.TokenRefreshSettings.RefreshWindowStart, 0.4},
		{"RefreshWindowEnd", settings.TokenRefreshSettings.RefreshWindowEnd, 0.5},
		{"MinRefreshTimeout", settings.TokenRefreshSettings.MinRefreshTimeout, 5 * time.Minute},
		{"RefreshRetryTimeout", settings.TokenRefreshSettings.RefreshRetryTimeout, 15 * time.Minute},
		// §5.9's pass
		{"PassMemoryByteCount", settings.KeychainSettings.PassMemoryByteCount, int64(64 * 1024 * 1024)},
		{"PassIterationCount", settings.KeychainSettings.PassIterationCount, 3},
		{"PassThreadCount", settings.KeychainSettings.PassThreadCount, 4},
		{"PassAttemptCount", settings.KeychainSettings.PassAttemptCount, 5},
		{"PassAttemptInterval", settings.KeychainSettings.PassAttemptInterval, 10 * time.Minute},
		// §16.4
		{"SessionCallCount", settings.Mcp.SessionCallCount, 8},
		{"SessionWriteRate", settings.Mcp.SessionWriteRate.Count, 20},
		{"SessionWriteRate", settings.Mcp.SessionWriteRate.Interval, 1 * time.Second},
		{"ResultByteCount", settings.Mcp.ResultByteCount, 256 * 1024},
		{"CallTimeout", settings.Mcp.CallTimeout, 30 * time.Second},
		// §16.7
		{"PayloadByteCount", settings.Ingest.PayloadByteCount, int64(1024 * 1024)},
		{"FileByteCount", settings.Ingest.FileByteCount, int64(8 * 1024 * 1024)},
		{"RunHourByteCount", settings.Ingest.RunHourByteCount, int64(256 * 1024 * 1024)},
		{"SpoolByteCount", settings.Ingest.SpoolByteCount, int64(1024 * 1024 * 1024)},
		{"TranscriptTailInterval", settings.Ingest.TranscriptTailInterval, 30 * time.Second},
		{"HookExitTimeout", settings.Ingest.HookExitTimeout, 300 * time.Millisecond},
		{"RestorePointByteCount", settings.Ingest.RestorePointByteCount, int64(256 * 1024 * 1024)},
		{"RestoreHoldTimeout", settings.Ingest.RestoreHoldTimeout, 10 * time.Minute},
		{"RestoreHoldByteCount", settings.Ingest.RestoreHoldByteCount, int64(8 * 1024 * 1024)},
		// §16.8
		{"PushEntryCount", settings.Record.PushEntryCount, 64},
		{"PushCoalesce", settings.Record.PushCoalesce, 1 * time.Second},
		{"ReachReceiptCoalesce", settings.Record.ReachReceiptCoalesce, 5 * time.Minute},
		{"CoverageIdleTimeout", settings.Record.CoverageIdleTimeout, 10 * time.Minute},
		{"TeamRecordKeepDays", settings.Record.TeamRecordKeepDays, 400},
		{"TeamRecordSearchableDays", settings.Record.TeamRecordSearchableDays, 90},
		// §5.4's search settings
		{"CacheByteCount", settings.Search.CacheByteCount, int64(4 * 1024 * 1024 * 1024)},
		{"MemoryByteCount", settings.Search.MemoryByteCount, int64(64 * 1024 * 1024)},
		{"VersionCacheByteCount", settings.Search.VersionCacheByteCount, int64(256 * 1024)},
		{"BackgroundByteCount", settings.Search.BackgroundByteCount, int64(1024 * 1024 * 1024)},
		{"MoreByteCount", settings.Search.MoreByteCount, int64(1024 * 1024 * 1024)},
		{"AllPolicy", settings.Search.AllPolicy, "background"},
		{"HintCoalesce", settings.Search.HintCoalesce, 1 * time.Minute},
		{"CursorTimeout", settings.Search.CursorTimeout, 10 * time.Minute},
		{"HeadRefreshInterval", settings.Search.HeadRefreshInterval, 10 * time.Minute},
		{"NonWriterSyncInterval", settings.Search.NonWriterSyncInterval, 15 * time.Minute},
		{"SessionSearchCount", settings.Search.SessionSearchCount, 2},
		{"SessionSearchRate", settings.Search.SessionSearchRate, SidecarRate{Count: 5, Burst: 10, Interval: 1 * time.Second}},
		{"SessionCursorCount", settings.Search.SessionCursorCount, 16},
		{"DaemonSearchCount", settings.Search.DaemonSearchCount, 4},
		{"PageCpu", settings.Search.PageCpu, 2 * time.Second},
		{"PageCandidateCount", settings.Search.PageCandidateCount, 1000},
		{"TooBroadCandidateCount", settings.Search.TooBroadCandidateCount, 20000},
		{"PageByteCount", settings.Search.PageByteCount, 64 * 1024},
		{"RemoteMode", settings.Search.RemoteMode, "on"},
		{"RemoteTimeout", settings.Search.RemoteTimeout, [2]time.Duration{3 * time.Second, 5 * time.Second}},
		{"RemoteServe", settings.Search.RemoteServe, true},
		{"RemoteSearchCount", settings.Search.RemoteSearchCount, 4},
		{"RemoteQueueCount", settings.Search.RemoteQueueCount, 16},
		{"RemoteQueueTimeout", settings.Search.RemoteQueueTimeout, 1 * time.Second},
		{"RemoteCpuPerMinute", settings.Search.RemoteCpuPerMinute, 30 * time.Second},
		{"RemoteCursorCount", settings.Search.RemoteCursorCount, 64},
		{"RemoteRequesterRate", settings.Search.RemoteRequesterRate, SidecarRate{Count: 30, Burst: 10, Interval: 1 * time.Minute}},
		{"ServedRecordTimeout", settings.Search.ServedRecordTimeout, 30 * 24 * time.Hour},
		// §5.4's directory settings
		{"SessionSyncInterval", settings.Directory.SessionSyncInterval, 15 * time.Minute},
		{"IdleSyncInterval", settings.Directory.IdleSyncInterval, 1 * time.Hour},
		{"ViewCoalesce", settings.Directory.ViewCoalesce, 30 * time.Second},
		{"PhoneMeteredByteCount", settings.Directory.PhoneMeteredByteCount, int64(8 * 1024 * 1024)},
		{"RenewJitter", settings.Directory.RenewJitter, 5 * time.Minute},
	}
	for _, check := range checks {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s: %v, want %v", check.name, check.got, check.want)
		}
	}
}

func TestDefaultProtocolSettingsMatchDesign(t *testing.T) {
	settings := DefaultSidecarSettings().ProtocolSettings

	// §6.6's desktop values, in its order
	want := &SidecarProtocolSettings{
		HelloCacheTimeout:               10 * time.Minute,
		MarkedKeepaliveInterval:         60 * time.Second,
		DefaultCallTimeout:              15 * time.Second,
		PeerQueueMessageCount:           64,
		ReassemblyMaxBodyByteCount:      256 * 1024,
		ReassemblyPeerCount:             8,
		ReassemblyPeerByteCount:         2 * 1024 * 1024,
		ReassemblyProcessByteCount:      16 * 1024 * 1024,
		ReassemblyIdleTimeout:           30 * time.Second,
		IdempotencyTimeout:              10 * time.Minute,
		IdempotencyPeerByteCount:        256 * 1024,
		IdempotencyProcessByteCount:     4 * 1024 * 1024,
		IdempotencyMaxResponseByteCount: 16 * 1024,
		StreamInitialWindowByteCount:    16 * 1024,
		StreamMinWindowByteCount:        256 * 1024,
		StreamMaxWindowByteCount:        1024 * 1024,
		StreamPeerCreditByteCount:       8 * 1024 * 1024,
		StreamProcessCreditByteCount:    64 * 1024 * 1024,
		StreamMaxPeerCreditFraction:     0.125,
		PingTimeout:                     15 * time.Second,
		PeerSilenceTimeout:              45 * time.Second,
		HeadCheckInterval:               1 * time.Hour,
		HeadCheckRoundPeerCount:         4,
		HeadCheckTimeout:                10 * time.Second,
		HeadCheckFetchTimeout:           10 * time.Minute,
		HeadCheckUnwitnessedInterval:    10 * time.Minute,
		WakeInterval:                    1 * time.Hour,
		SyncRefetchInterval:             1 * time.Hour,
	}
	if *settings != *want {
		t.Errorf("%+v, want %+v", *settings, *want)
	}
}

// The numbers §5.4 leaves open, pinned here so a change to one is deliberate. Each is a reading the
// report names, not a design value.
func TestDefaultSettingsTheDesignLeavesOpen(t *testing.T) {
	settings := DefaultSidecarSettings()

	if settings.KeychainSettings.AutoLockTimeout != 0 {
		t.Errorf("AutoLockTimeout %v: an unattended daemon must not lock itself", settings.KeychainSettings.AutoLockTimeout)
	}
	if settings.LocalSettings.SocketPath != "" || settings.LocalSettings.AppGroupSocketPath != "" {
		t.Errorf("socket paths %+v: empty derives §5.9's", settings.LocalSettings)
	}
	if settings.LocalSettings.IdleExitTimeout <= 0 || settings.LocalSettings.RequestTimeout <= 0 {
		t.Errorf("local bounds %+v", settings.LocalSettings)
	}
	// a hook payload at its limit fits in one request, with room for JSON's escaping
	if settings.LocalSettings.RequestByteCount < 2*settings.Ingest.PayloadByteCount {
		t.Errorf("RequestByteCount %d", settings.LocalSettings.RequestByteCount)
	}
	// 256 envelopes of 4,080 B, each in its 4 KiB pool class
	if settings.ComponentQueueByteCount != settings.ComponentQueueMessageCount*4096 {
		t.Errorf("queue %d messages, %d bytes", settings.ComponentQueueMessageCount, settings.ComponentQueueByteCount)
	}
}

// No environment's url lives in code: a host sets them. A dial on an empty url fails, so a host that
// forgets gets an error, not a production service.
func TestDefaultServiceUrlsAreUnset(t *testing.T) {
	settings := DefaultSidecarSettings()
	for name, url := range map[string]string{
		"ApiUrl":      settings.ApiUrl,
		"PlatformUrl": settings.PlatformUrl,
		"AuthUrl":     settings.AuthUrl,
		"EvsUrl":      settings.EvsUrl,
		"GkmUrl":      settings.GkmUrl,
		"SocketsUrl":  settings.SocketsUrl,
		"DnsUrl":      settings.DnsUrl,
	} {
		if url != "" {
			t.Errorf("%s defaults to %q", name, url)
		}
	}
}

func TestDefaultSidecarSettingsFillEveryPointer(t *testing.T) {
	settings := reflect.ValueOf(DefaultSidecarSettings()).Elem()
	for i := 0; i < settings.NumField(); i += 1 {
		field := settings.Field(i)
		if field.Kind() == reflect.Pointer && field.IsNil() {
			t.Errorf("%s is nil", settings.Type().Field(i).Name)
		}
	}
}

// Hosts adjust what they get, so two owners must not share a settings value. Budgets are owned by
// instances, not by the process (connect/CODESTYLE.md:151).
func TestDefaultSidecarSettingsShareNothing(t *testing.T) {
	first := reflect.ValueOf(DefaultSidecarSettings()).Elem()
	second := reflect.ValueOf(DefaultSidecarSettings()).Elem()
	for i := 0; i < first.NumField(); i += 1 {
		field := first.Field(i)
		// pointers to a zero-size value may compare equal with nothing behind them to share, as the
		// sidecar_http leg's empty SidecarConnectSettings shows
		if field.Kind() != reflect.Pointer || field.Type().Elem().Size() == 0 {
			continue
		}
		if field.Pointer() == second.Field(i).Pointer() {
			t.Errorf("%s is shared between calls", first.Type().Field(i).Name)
		}
	}
}

func TestAdjustingDefaultsLeavesTheNextAlone(t *testing.T) {
	adjusted := DefaultSidecarSettings()
	adjusted.Search.MemoryByteCount = 1
	adjusted.ProtocolSettings.ReassemblyPeerCount = 1
	adjusted.Directory.ViewCoalesce = 1

	settings := DefaultSidecarSettings()
	if settings.Search.MemoryByteCount != 64*1024*1024 ||
		settings.ProtocolSettings.ReassemblyPeerCount != 8 ||
		settings.Directory.ViewCoalesce != 30*time.Second {
		t.Errorf("an adjustment reached the next default: %+v", settings)
	}
}

// §6.7's windows and §5.4's budget have to hold together for a stream to open at all.
func TestDefaultProtocolBoundsAreConsistent(t *testing.T) {
	settings := DefaultSidecarSettings()
	protocol := settings.ProtocolSettings

	if protocol.DefaultCallTimeout > 55*time.Second {
		t.Errorf("DefaultCallTimeout %v past the protocol's 55 s", protocol.DefaultCallTimeout)
	}
	if protocol.ReassemblyMaxBodyByteCount > 1024*1024 {
		t.Errorf("ReassemblyMaxBodyByteCount %d past the protocol's 1 MiB", protocol.ReassemblyMaxBodyByteCount)
	}
	if protocol.StreamMaxWindowByteCount < protocol.StreamMinWindowByteCount {
		t.Errorf("stream window %d to %d", protocol.StreamMinWindowByteCount, protocol.StreamMaxWindowByteCount)
	}
	if protocol.StreamPeerCreditByteCount < protocol.StreamMinWindowByteCount {
		t.Errorf("peer credit %d under a stream's minimum window", protocol.StreamPeerCreditByteCount)
	}
	if protocol.StreamProcessCreditByteCount < protocol.StreamPeerCreditByteCount {
		t.Errorf("process credit %d under a peer's", protocol.StreamProcessCreditByteCount)
	}
	// connect exits a silent sequence at 60 s, which this must beat
	if 60*time.Second <= protocol.PeerSilenceTimeout || protocol.PeerSilenceTimeout <= protocol.PingTimeout {
		t.Errorf("silence %v, ping %v", protocol.PeerSilenceTimeout, protocol.PingTimeout)
	}
	for _, byteCount := range []int64{
		protocol.ReassemblyProcessByteCount,
		protocol.IdempotencyProcessByteCount,
		protocol.StreamProcessCreditByteCount,
		settings.Search.MemoryByteCount,
	} {
		if settings.MemoryBudgetByteCount < byteCount {
			t.Errorf("a cap of %d is past the budget's %d", byteCount, settings.MemoryBudgetByteCount)
		}
	}
}
