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
				StateJsonMaxByteCount: 1024 * 1024,
				PassMemoryByteCount:   testLegPassMemoryByteCount,
				PassIterationCount:    testLegPassIterationCount,
				PassThreadCount:       testLegPassThreadCount,
				PassAttemptCount:      5,
				PassAttemptInterval:   10 * time.Minute,
				AutoLockTimeout:       settings.KeychainSettings.AutoLockTimeout,
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
				// MCP-M3-13's reading: a read's in-memory bound, past §16.4's result cap
				ResourceByteCount: 16 * 1024 * 1024,
				// §16.6's retention row
				ApprovalFileRetention: 30 * 24 * time.Hour,
				RunFileRetention:      30 * 24 * time.Hour,
				// a run file's read bound (HARN-M11-02's move of record_run.go's constant, QD-702)
				RunFileByteCount: 1024 * 1024,
				// MCP.md's reading 3, §16.6's expiry row, and MCP-M3-05's poll, a reading
				ApprovalRequestTimeout:  24 * time.Hour,
				ApprovalCompleteTimeout: 10 * time.Minute,
				ApprovalPollInterval:    30 * time.Second,
				// §11.10's renew row, for a phone's approval leases (MCP-M8-01)
				ApprovalPhoneLeaseRenewAge: 24 * time.Hour,
				ApprovalPhoneLeaseExpiry:   7 * 24 * time.Hour,
				// MCP-M3-09's reading: §7.9 requires a presence key's not_after and states none
				PresenceKeyLifetime: 365 * 24 * time.Hour,
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
				RunHourInterval:        1 * time.Hour,
				SpoolByteCount:         1024 * 1024 * 1024,
				SpoolSegmentByteCount:  16 * 1024 * 1024,
				SpoolCursorRecordCount: 64,
				TranscriptTailInterval: 30 * time.Second,
				HookExitTimeout:        300 * time.Millisecond,
				// plan-MCP-presence-hook-timing: the presence prompt's bound
				PresencePromptTimeout: 60 * time.Second,
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
				IngestStateByteCount:  1024 * 1024,
				IngestBlobHashCount:   4096,
				// MCP-M3-21's readings for the restore point's files, the apply's hidden names and its copies
				RestoreManifestByteCount:   64 * 1024 * 1024,
				RestorePreviewCount:        16,
				RestoreHiddenNameByteCount: 16,
				RestoreCopyNameCount:       1024,
				// §16.6's modes whose evidence never counts, and MCP-M3-19's readings of §16.7's context and run card
				BypassPermissionModes: []string{"bypassPermissions", "dontAsk", "auto"},
				InstructionProjectFileNames: []string{
					"CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md", "AGENTS.md", ".cursorrules", ".cursor/rules",
				},
				InstructionUserFileNames: []string{".claude/CLAUDE.md", ".codex/AGENTS.md"},
				ChangePathCount:          4096,
				RunCardPromptByteCount:   2 * 1024,
				RunCardPathCount:         256,
				// MCP-M10-02: RECORD.md section 6.4's tool_name and tool paths caps, ingest_tools.go's literals before
				// QD-702's move, and the transcript's skip buffer, ingest_transcript.go's
				ToolNameByteCount:       64,
				ToolPathCount:           256,
				TranscriptSkipByteCount: 64 * 1024,
				// RECORD.md section 6.4's ContextBody caps, ingest_context.go's constants before QD-702's move, the
				// harness version's 64 B a reading and a truncation's file name 100 B of its 128
				ContextTitleByteCount:               120,
				ContextSessionIdCount:               4,
				ContextSessionIdByteCount:           64,
				ContextHarnessVersionByteCount:      64,
				ContextModelByteCount:               64,
				ContextPermissionModeByteCount:      32,
				ProjectByteCount:                    128,
				ContextBranchByteCount:              128,
				ContextInstructionFileCount:         64,
				ContextInstructionFileNameByteCount: 128,
				ContextTruncationCount:              16,
				ContextTruncationNameByteCount:      100,
				// §16.5's agent-config files, and MCP-M3-16's and MCP-M3-10's readings of §16.6 and §16.7
				AgentConfigPaths: []string{
					"CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", ".mcp.json", ".cursorrules",
					".claude/settings.json", ".claude/settings.local.json",
					".codex/config.toml", ".codex/hooks.json",
					".cursor/mcp.json", ".cursor/hooks.json",
					".ur",
				},
				HarnessConfigByteCount:      16 * 1024 * 1024,
				HarnessConfigDepthCount:     64,
				HarnessConfigEditCount:      1024,
				HarnessDiffContextLineCount: 3,
				PermissionHookTimeout:       75 * time.Second,
				HarnessInstallRetryCount:    3,
				HarnessEvidenceTimeout:      10 * time.Minute,
				HarnessEvidenceEventCount:   1024,
				HarnessPromptingModes:       []string{"default", "acceptEdits", "plan"},
				// §16.18's v1 capture (MCP-M6-03), off by default
				FileEvents:              false,
				FileEventDirectoryCount: 4096,
				ModelCalls:              false,
				TelemetryByteCount:      4 * 1024 * 1024,
				ModelCallFieldByteCount: 128,
				// the telemetry listener and its token (QD-822): the token's 32 bytes are the owner's, the rest are
				// readings
				TelemetryTokenByteCount:  32,
				TelemetryRequestRate:     SidecarRate{Count: 4, Burst: 16, Interval: 1 * time.Second},
				TelemetryRequestTimeout:  30 * time.Second,
				TelemetryHeaderByteCount: 64 * 1024,
				TelemetryShutdownTimeout: 5 * time.Second,
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
				ExportJobByteCount:   1024 * 1024,
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
				CacheHoldingsByteCount: 16 * 1024 * 1024,
				CacheMetaByteCount:     64 * 1024,
				EraseMaskCount:         16384,
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
				ServedRecordCount:      8192,
				RemoteServedTimeout:    24 * time.Hour,
				StateByteCount:         4 * 1024 * 1024,
				PageHitCount:           50,

				RemoteCpuWindow:                 1 * time.Minute,
				RemoteSearchMemoryByteCount:     8 * 1024 * 1024,
				ServeRecheckInterval:            10 * time.Minute,
				DesignatedCacheByteCount:        16 * 1024 * 1024 * 1024,
				DesignatedMemoryBudgetByteCount: 192 * 1024 * 1024,
				VersionPageByteCount:            4 * 1024,
				VersionMergeInputCount:          16,
				VersionMergeByteCount:           1024 * 1024,
				// DESIGN-DETAILS 7.2.1's sync settings; the restart bound is a reading
				ResyncInterval:    1 * time.Hour,
				SyncRoundCount:    4,
				SyncRetryInterval: 30 * time.Second,
				PinRingCount:      64,
				RetainFactor:      2,
				SyncRestartCount:  4,
				// QD-511's companion interval; the journal's bound and the build count are readings
				CompanionInterval:     5 * time.Minute,
				JournalByteCount:      64 * 1024 * 1024,
				CompanionAttemptCount: 8,
				MeteredMoreByteCount:  25 * 1024 * 1024,
				DirectoryBuckets:      true,
				MoreFirstProgress:     500 * time.Millisecond,
				MoreProgressInterval:  1 * time.Second,
				// DESIGN-DETAILS 7.2.1's asker and merge settings (QD-707, QD-709); the ended ids' bound, the retry, reopen
				// and seen-again counts and the pins that wait are readings of counts the design names
				RemoteOwnAskCount:          2,
				RemoteSkipTimeout:          2 * time.Minute,
				RemoteOnlineTimeout:        10 * time.Minute,
				RemoteRefusedTimeout:       10 * time.Minute,
				RemoteMismatchCount:        3,
				RemoteMismatchInterval:     24 * time.Hour,
				RemoteDistrustTimeout:      24 * time.Hour,
				SkewGuard:                  40 * time.Minute,
				RemoteRequesterCursorCount: 2,
				RemoteEndedIdCount:         300,
				RemotePageRetryCount:       1,
				RemoteReopenCount:          1,
				RemoteSeenAgainCount:       1,
				RemoteClaimCount:           20000,
				RemotePinWaitCount:         64,
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
				PhoneVersionByteCount: 1536 + 800,
				RenewJitter:           5 * time.Minute,
				PhoneLeaseRenewAge:    24 * time.Hour,
				PhoneLeaseExpiry:      7 * 24 * time.Hour,
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
		HeadCheckRoundOtherMemberCount:   2,
		HeadCheckTimeout:                 10 * time.Second,
		HeadCheckFetchTimeout:            10 * time.Minute,
		HeadCheckUnwitnessedInterval:     10 * time.Minute,
		WakeInterval:                     1 * time.Hour,
		SyncRefetchInterval:              1 * time.Hour,
		// §6.5's StreamOpen budget (QD-702: protocol limits are settings)
		StreamTargetMaxByteCount:   128,
		StreamMetadataMaxByteCount: 1024,
		StreamTicketMaxByteCount:   512,
		StreamOpenMaxByteCount:     3800,
		// D-PROTO-10: relay-only until the owner's call on FS-126
		EnablePeerP2p: false,
	}
	// SEARCH's wire values, §6.5's and DESIGN-DETAILS 11.2.9's
	want.Search = SearchWireSettings{
		RequestByteCount:         4016,
		Timeout:                  10 * time.Second,
		StepByteCount:            16384,
		MaxStepCount:             4,
		PadLengthMinByteCount:    2,
		PadLengthMaxByteCount:    3,
		QueryMaxByteCount:        512,
		RepoMaxCount:             64,
		IdByteCount:              16,
		FiltersMaxByteCount:      768,
		CoverageMaxCount:         64,
		ChainMaxByteCount:        32,
		HitMaxCount:              20,
		LocatorMaxByteCount:      512,
		CorrectionMaxByteCount:   256,
		HitFieldMaxCount:         8,
		HitFieldTextMaxByteCount: 256,
		SnippetMaxByteCount:      200,
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
		IdleExitTimeout:        10 * time.Minute,
		RequestByteCount:       4 * 1024 * 1024,
		RequestTimeout:         30 * time.Second,
		FirstPort:              17000,
		HelloByteCount:         16 * 1024,
		SessionBufferByteCount: 4 * 1024,
		ReplyMaxDepth:          32,
		EventRingEventCount:    1024,
		EventReplyEventCount:   256,
		EventWaitTimeout:       25 * time.Second,
		PresenceActTimeout:     2 * time.Minute,
		PresenceActCount:       16,
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
	// §7.4's reading (QD-757): a round trip's reading is good to half of it, and a retry's shift lies between a
	// Date's whole second and §7.4's window
	if settings.ApiClockMaxRoundTrip != 30*time.Second || settings.ApiClockRetryShift != 5*time.Second {
		t.Errorf("ApiClockMaxRoundTrip %s ApiClockRetryShift %s", settings.ApiClockMaxRoundTrip, settings.ApiClockRetryShift)
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
	// an events call's wait answers before the request bound would, and a reply's events fit the ring
	if settings.LocalSettings.RequestTimeout <= settings.LocalSettings.EventWaitTimeout ||
		settings.LocalSettings.EventRingEventCount < settings.LocalSettings.EventReplyEventCount {
		t.Errorf("EventWaitTimeout %v, EventReplyEventCount %d", settings.LocalSettings.EventWaitTimeout, settings.LocalSettings.EventReplyEventCount)
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
