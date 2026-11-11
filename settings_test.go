package sidecar

import (
	"reflect"
	"testing"
	"time"
)

// Every default the design states, whole struct by whole struct, so a field added with a value fails
// here until its row is. The readings the design leaves open are held by
// TestDefaultSettingsTheDesignLeavesOpen.
func TestDefaultSidecarSettingsMatchDesign(t *testing.T) {
	settings := DefaultSidecarSettings()

	checks := []struct {
		name string
		got  any
		want any
	}{
		// §5.9, §18.4
		{name: "Instance", got: settings.Instance, want: "default"},
		{name: "MemoryBudgetByteCount", got: settings.MemoryBudgetByteCount, want: int64(128 * 1024 * 1024)},
		// §6.5's StreamData limit
		{name: "StreamChunkByteCount", got: settings.StreamChunkByteCount, want: 4000},
		{name: "Log", got: settings.Log, want: nil},
		// §5.4: sdk's schedule
		{
			name: "TokenRefreshSettings",
			got:  *settings.TokenRefreshSettings,
			want: SidecarTokenRefreshSettings{
				RefreshWindowStart:         0.4,
				RefreshWindowEnd:           0.5,
				MinRefreshTimeout:          5 * time.Minute,
				RefreshRetryTimeout:        15 * time.Minute,
				NoExpirationRefreshTimeout: 7 * 24 * time.Hour,
				ServiceTokenCacheTimeout:   10 * time.Minute,
			},
		},
		// §5.9's pass, at the leg's Argon2id cost (TestPassCostOnThisLeg); auto-lock is a reading
		{
			name: "KeychainSettings",
			got:  *settings.KeychainSettings,
			want: SidecarKeychainSettings{
				PassMemoryByteCount: testLegPassMemoryByteCount,
				PassIterationCount:  testLegPassIterationCount,
				PassThreadCount:     testLegPassThreadCount,
				PassAttemptCount:    5,
				PassAttemptInterval: 10 * time.Minute,
				AutoLockTimeout:     settings.KeychainSettings.AutoLockTimeout,
			},
		},
		// §16.4; the burst is a reading
		{
			name: "Mcp",
			got:  *settings.Mcp,
			want: SidecarMcpSettings{
				SessionCallCount: 8,
				SessionWriteRate: SidecarRate{Count: 20, Burst: settings.Mcp.SessionWriteRate.Burst, Interval: 1 * time.Second},
				ResultByteCount:  256 * 1024,
				CallTimeout:      30 * time.Second,
				// §16.6's retention row
				ApprovalFileRetention: 30 * 24 * time.Hour,
				RunFileRetention:      30 * 24 * time.Hour,
				// I-7's matcher (record_secret_match.go)
				SecretMatch: &SecretMatchSettings{CredentialMinByteCount: 16},
			},
		},
		// §16.7
		{
			name: "Ingest",
			got:  *settings.Ingest,
			want: SidecarIngestSettings{
				PayloadByteCount:       1024 * 1024,
				FileByteCount:          8 * 1024 * 1024,
				RunHourByteCount:       256 * 1024 * 1024,
				SpoolByteCount:         1024 * 1024 * 1024,
				SpoolSegmentByteCount:  16 * 1024 * 1024,
				SpoolCursorRecordCount: 64,
				TranscriptTailInterval: 30 * time.Second,
				HookExitTimeout:        300 * time.Millisecond,
				// MCP.md's MCP-M3-15 readings: a PreToolUse's wait for its paths, and the ancestry walk's bound
				HookPathTimeout: 10 * time.Second,
				// §16.6's taint row: 60 s either side of a call, and a config check every 5 min
				HookLapseTimeout:    60 * time.Second,
				ConfigCheckInterval: 5 * time.Minute,
				// §16.6's web tools (MCP.md's reading 12), and the shells the ancestry rules step over
				WebToolNames: []string{"WebFetch", "WebSearch", "web_search", "web_fetch", "curl", "wget"},
				ShellNames: []string{
					"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "tcsh", "csh", "nu", "cmd", "powershell", "pwsh",
				},
				AncestorDepthCount:    64,
				RestorePointByteCount: 256 * 1024 * 1024,
				RestoreHoldTimeout:    10 * time.Minute,
				RestoreHoldByteCount:  8 * 1024 * 1024,
				// §16.6's modes whose evidence never counts, and MCP-M3-19's readings of §16.7's context and run card
				BypassPermissionModes: []string{"bypassPermissions", "dontAsk", "auto"},
				InstructionProjectFileNames: []string{
					"CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md", "AGENTS.md", ".cursorrules", ".cursor/rules",
				},
				InstructionUserFileNames: []string{".claude/CLAUDE.md", ".codex/AGENTS.md"},
				ChangePathCount:          4096,
				RunCardPromptByteCount:   2 * 1024,
				RunCardPathCount:         256,
			},
		},
		// §16.8
		{
			name: "Record",
			got:  *settings.Record,
			want: SidecarRecordSettings{
				PushEntryCount:           64,
				PushCoalesce:             1 * time.Second,
				ReachReceiptCoalesce:     5 * time.Minute,
				CoverageIdleTimeout:      10 * time.Minute,
				TeamRecordKeepDays:       400,
				TeamRecordSearchableDays: 90,
				// RECORD.md section 18
				DepositInterval:      5 * time.Minute,
				DepositByteCount:     1024 * 1024,
				TimeSkewTimeout:      10 * time.Minute,
				ChainGapTimeout:      1 * time.Hour,
				CardInterval:         5 * time.Minute,
				ExpiryInterval:       24 * time.Hour,
				ExpiryDelay:          10 * time.Minute,
				BaseInterval:         7 * 24 * time.Hour,
				CheckpointInterval:   1 * time.Hour,
				WitnessTimeout:       60 * time.Second,
				WitnessFreshInterval: 24 * time.Hour,
				WitnessMissCount:     3,
				LeafBatchCount:       32768,
			},
		},
		// §5.4's search settings
		{
			name: "Search",
			got:  *settings.Search,
			want: SidecarSearchSettings{
				CacheByteCount:         4 * 1024 * 1024 * 1024,
				MemoryByteCount:        64 * 1024 * 1024,
				VersionCacheByteCount:  256 * 1024,
				BackgroundByteCount:    1024 * 1024 * 1024,
				MoreByteCount:          1024 * 1024 * 1024,
				AllPolicy:              "background",
				HintCoalesce:           1 * time.Minute,
				CursorTimeout:          10 * time.Minute,
				HeadRefreshInterval:    10 * time.Minute,
				NonWriterSyncInterval:  15 * time.Minute,
				SessionSearchCount:     2,
				SessionSearchRate:      SidecarRate{Count: 5, Burst: 10, Interval: 1 * time.Second},
				SessionCursorCount:     16,
				DaemonSearchCount:      4,
				PageCpu:                2 * time.Second,
				PageCandidateCount:     1000,
				TooBroadCandidateCount: 20000,
				PageByteCount:          64 * 1024,
				RemoteMode:             "on",
				RemoteTimeout:          [2]time.Duration{3 * time.Second, 5 * time.Second},
				RemoteServe:            true,
				RemoteSearchCount:      4,
				RemoteQueueCount:       16,
				RemoteQueueTimeout:     1 * time.Second,
				RemoteCpuPerMinute:     30 * time.Second,
				RemoteCursorCount:      64,
				RemoteRequesterRate:    SidecarRate{Count: 30, Burst: 10, Interval: 1 * time.Minute},
				ServedRecordTimeout:    30 * 24 * time.Hour,
			},
		},
		// §5.4's directory settings
		{
			name: "Directory",
			got:  *settings.Directory,
			want: SidecarDirectorySettings{
				SessionSyncInterval:   15 * time.Minute,
				IdleSyncInterval:      1 * time.Hour,
				ViewCoalesce:          30 * time.Second,
				PhoneMeteredByteCount: 8 * 1024 * 1024,
				RenewJitter:           5 * time.Minute,
			},
		},
	}
	for _, check := range checks {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s: %+v, want %+v", check.name, check.got, check.want)
		}
	}
}

// Version is empty in a development build, so comparing against it in place would pass with the field
// unset: this gives it a release's value first.
func TestDefaultAppVersionIsTheReleaseVersion(t *testing.T) {
	defer func(version string) { Version = version }(Version)
	Version = "2026.11.6-synthetic"
	if appVersion := DefaultSidecarSettings().AppVersion; appVersion != "2026.11.6-synthetic" {
		t.Errorf("AppVersion %q", appVersion)
	}
}

func TestDefaultProtocolSettingsMatchDesign(t *testing.T) {
	settings := DefaultSidecarSettings().ProtocolSettings

	// §6.6's desktop values, in its order, with §6.7's minimum above half of GOMEMLIMIT after the
	// minimum it stands in for
	want := &SidecarProtocolSettings{
		HelloCacheTimeout:                10 * time.Minute,
		MarkedKeepaliveInterval:          60 * time.Second,
		MarkedSessionTimeout:             120 * time.Second,
		DefaultCallTimeout:               15 * time.Second,
		HelloUnknownPeerCount:            1024,
		CallSendRetryInterval:            250 * time.Millisecond,
		PeerQueueMessageCount:            64,
		ReassemblyMaxBodyByteCount:       256 * 1024,
		ReassemblyPeerCount:              8,
		ReassemblyPeerByteCount:          2 * 1024 * 1024,
		ReassemblyProcessByteCount:       16 * 1024 * 1024,
		ReassemblyIdleTimeout:            30 * time.Second,
		IdempotencyTimeout:               10 * time.Minute,
		IdempotencyPeerByteCount:         256 * 1024,
		IdempotencyProcessByteCount:      4 * 1024 * 1024,
		IdempotencyMaxResponseByteCount:  16 * 1024,
		StreamInitialWindowByteCount:     16 * 1024,
		StreamMinWindowByteCount:         256 * 1024,
		StreamPressureMinWindowByteCount: 64 * 1024,
		StreamMaxWindowByteCount:         1024 * 1024,
		StreamPeerCreditByteCount:        8 * 1024 * 1024,
		StreamProcessCreditByteCount:     64 * 1024 * 1024,
		StreamMaxPeerCreditFraction:      0.125,
		PingTimeout:                      15 * time.Second,
		PeerSilenceTimeout:               45 * time.Second,
		HeadCheckInterval:                1 * time.Hour,
		HeadCheckRoundPeerCount:          4,
		HeadCheckTimeout:                 10 * time.Second,
		HeadCheckFetchTimeout:            10 * time.Minute,
		HeadCheckUnwitnessedInterval:     10 * time.Minute,
		WakeInterval:                     1 * time.Hour,
		SyncRefetchInterval:              1 * time.Hour,
	}
	if *settings != *want {
		t.Errorf("%+v, want %+v", *settings, *want)
	}
}

// The numbers the design leaves open, pinned exactly, so a change to one is deliberate. Each is a
// reading raised with the owner, not a design value.
func TestDefaultSettingsTheDesignLeavesOpen(t *testing.T) {
	settings := DefaultSidecarSettings()

	// §5.4 names auto-lock with no value, so it stays on the side that protects keys
	if settings.KeychainSettings.AutoLockTimeout != 10*time.Minute {
		t.Errorf("AutoLockTimeout %v", settings.KeychainSettings.AutoLockTimeout)
	}
	wantLocal := SidecarLocalSettings{
		IdleExitTimeout:  10 * time.Minute,
		RequestByteCount: 4 * 1024 * 1024,
		RequestTimeout:   30 * time.Second,
		FirstPort:        17000,
	}
	if *settings.LocalSettings != wantLocal {
		t.Errorf("local settings %+v, want %+v", *settings.LocalSettings, wantLocal)
	}
	if settings.ComponentQueueMessageCount != 256 {
		t.Errorf("ComponentQueueMessageCount %d", settings.ComponentQueueMessageCount)
	}
	if settings.ComponentQueueByteCount != 1024*1024 {
		t.Errorf("ComponentQueueByteCount %d", settings.ComponentQueueByteCount)
	}
	if settings.Mcp.SessionWriteRate.Burst != 20 {
		t.Errorf("SessionWriteRate.Burst %d", settings.Mcp.SessionWriteRate.Burst)
	}
	// connect's MaxHttpResponseBodyBytes, the bound connect puts on an api answer
	if settings.ApiResponseByteCount != 2*1024*1024 {
		t.Errorf("ApiResponseByteCount %d", settings.ApiResponseByteCount)
	}

	// why those numbers hold together: a hook payload at its limit fits in one request with room for
	// JSON's escaping, a local request gets a call's time, and a full queue of 4,080 B envelopes fits
	// its bytes, each in its 4 KiB pool class
	if settings.LocalSettings.RequestByteCount < 2*settings.Ingest.PayloadByteCount {
		t.Errorf("RequestByteCount %d", settings.LocalSettings.RequestByteCount)
	}
	if settings.LocalSettings.RequestTimeout != settings.Mcp.CallTimeout {
		t.Errorf("RequestTimeout %v", settings.LocalSettings.RequestTimeout)
	}
	if settings.ComponentQueueByteCount != settings.ComponentQueueMessageCount*4096 {
		t.Errorf("queue %d messages, %d bytes", settings.ComponentQueueMessageCount, settings.ComponentQueueByteCount)
	}
}

// No environment's url lives in code: a host sets them. validate refuses one left empty, so a host
// that forgets gets an error from NewSidecar, on the one leg where a dial would not give it one
// (TestDefaultSettingsRefuseUntilAHostSetsItsUrls).
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
