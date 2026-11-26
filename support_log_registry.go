// Code generated from support/registry.yml by check/support_log_test.go. DO NOT EDIT.

//go:build !ios_extension && !sidecar_http

// The support log's registry, version 2 (DESIGN-COMPUTE §28.7): its components, codes, enums and fields, and a
// constructor for each field, which is the only way to give Event a field. support/registry.yml is the source;
// regenerate this file with
//
//	SIDECAR_REGENERATE_SUPPORT_LOG=1 go test -tags sidecar_check -run '^TestSupportLogRegistryIsCurrent$' ./check

package sidecar

import (
	"time"
)

// The registry's version, which every bundle's header names.
const SupportLogRegistryVersion = 2

// The registry's components.
const (
	SupportLogComponentSupportLog SupportLogComponent = 1
	SupportLogComponentDaemon     SupportLogComponent = 2
	SupportLogComponentApp        SupportLogComponent = 3
	SupportLogComponentSupport    SupportLogComponent = 4
)

// The registry's codes, each with its severity and the fields it declares.
const (
	// support_log.opened, info: segments, ring_bytes
	SupportLogCodeSupportLogOpened SupportLogCode = 1
	// support_log.events_dropped, degraded: count
	SupportLogCodeSupportLogEventsDropped SupportLogCode = 2
	// support_log.segment_pruned, info: prune_reason, segments
	SupportLogCodeSupportLogSegmentPruned SupportLogCode = 3
	// support_log.segment_unreadable, degraded: unreadable_reason
	SupportLogCodeSupportLogSegmentUnreadable SupportLogCode = 4
	// support_log.field_refused, degraded: count
	SupportLogCodeSupportLogFieldRefused SupportLogCode = 5
	// support_log.write_failed, failed: count
	SupportLogCodeSupportLogWriteFailed SupportLogCode = 6
	// daemon.started, info: release, auto_spawned
	SupportLogCodeDaemonStarted SupportLogCode = 7
	// daemon.stopped, info: stop_reason, uptime
	SupportLogCodeDaemonStopped SupportLogCode = 8
	// app.started, info: release
	SupportLogCodeAppStarted SupportLogCode = 9
	// app.stopped, info: uptime
	SupportLogCodeAppStopped SupportLogCode = 10
	// support.message_refused, degraded: refusal, tier, agent, run
	SupportLogCodeSupportMessageRefused SupportLogCode = 11
	// support.message_queued, info: outcome, tier, body_bytes, with_bundle, files, tainted, decider, agent, run, request
	SupportLogCodeSupportMessageQueued SupportLogCode = 12
	// support.message_posted, info: post_result, attempts, waited, entry
	SupportLogCodeSupportMessagePosted SupportLogCode = 13
	// support.post_failed, degraded: post_result, attempts
	SupportLogCodeSupportPostFailed SupportLogCode = 14
	// support.message_given_up, failed: attempts, waited, entry
	SupportLogCodeSupportMessageGivenUp SupportLogCode = 15
	// support.stream_changed, info: stream_state, post_result
	SupportLogCodeSupportStreamChanged SupportLogCode = 16
	// support.event_received, info: entry
	SupportLogCodeSupportEventReceived SupportLogCode = 17
	// support.token_failed, degraded: post_result
	SupportLogCodeSupportTokenFailed SupportLogCode = 18
)

// The registry's enum decider.
type SupportLogDecider uint32

const (
	SupportLogDeciderNone       SupportLogDecider = 1
	SupportLogDeciderClassifier SupportLogDecider = 2
	SupportLogDeciderPerson     SupportLogDecider = 3
)

// The registry's enum outcome.
type SupportLogOutcome uint32

const (
	SupportLogOutcomeSent            SupportLogOutcome = 1
	SupportLogOutcomeQueued          SupportLogOutcome = 2
	SupportLogOutcomeApprovalPending SupportLogOutcome = 3
	SupportLogOutcomeDeclined        SupportLogOutcome = 4
	SupportLogOutcomeNotSent         SupportLogOutcome = 5
)

// The registry's enum post_result.
type SupportLogPostResult uint32

const (
	SupportLogPostResultAccepted     SupportLogPostResult = 1
	SupportLogPostResultReplayed     SupportLogPostResult = 2
	SupportLogPostResultClientError  SupportLogPostResult = 3
	SupportLogPostResultRateLimited  SupportLogPostResult = 4
	SupportLogPostResultServerError  SupportLogPostResult = 5
	SupportLogPostResultUnreachable  SupportLogPostResult = 6
	SupportLogPostResultTlsFailed    SupportLogPostResult = 7
	SupportLogPostResultTimeout      SupportLogPostResult = 8
	SupportLogPostResultUnauthorized SupportLogPostResult = 9
)

// The registry's enum prune_reason.
type SupportLogPruneReason uint32

const (
	SupportLogPruneReasonAge  SupportLogPruneReason = 1
	SupportLogPruneReasonSize SupportLogPruneReason = 2
)

// The registry's enum refusal.
type SupportLogRefusal uint32

const (
	SupportLogRefusalDisclosureRequired SupportLogRefusal = 1
	SupportLogRefusalSecretInMessage    SupportLogRefusal = 2
	SupportLogRefusalHiddenText         SupportLogRefusal = 3
	SupportLogRefusalSupportOff         SupportLogRefusal = 4
	SupportLogRefusalRateLimited        SupportLogRefusal = 5
	SupportLogRefusalSupportQueueFull   SupportLogRefusal = 6
	SupportLogRefusalSupportPaused      SupportLogRefusal = 7
	SupportLogRefusalTooLong            SupportLogRefusal = 8
	SupportLogRefusalNotText            SupportLogRefusal = 9
	SupportLogRefusalFileRefused        SupportLogRefusal = 10
	SupportLogRefusalNotFound           SupportLogRefusal = 11
	SupportLogRefusalNoHost             SupportLogRefusal = 12
	SupportLogRefusalGrantRequired      SupportLogRefusal = 13
)

// The registry's enum stop_reason.
type SupportLogStopReason uint32

const (
	SupportLogStopReasonIdle   SupportLogStopReason = 1
	SupportLogStopReasonSignal SupportLogStopReason = 2
	SupportLogStopReasonClosed SupportLogStopReason = 3
	SupportLogStopReasonFailed SupportLogStopReason = 4
)

// The registry's enum stream_state.
type SupportLogStreamState uint32

const (
	SupportLogStreamStateOpened SupportLogStreamState = 1
	SupportLogStreamStateClosed SupportLogStreamState = 2
	SupportLogStreamStateFailed SupportLogStreamState = 3
)

// The registry's enum tier.
type SupportLogTier uint32

const (
	SupportLogTierHuman    SupportLogTier = 1
	SupportLogTierReleased SupportLogTier = 2
	SupportLogTierAgent    SupportLogTier = 3
	SupportLogTierAuto     SupportLogTier = 4
)

// The registry's enum unreadable_reason.
type SupportLogUnreadableReason uint32

const (
	SupportLogUnreadableReasonTruncated SupportLogUnreadableReason = 1
	SupportLogUnreadableReasonChecksum  SupportLogUnreadableReason = 2
	SupportLogUnreadableReasonMalformed SupportLogUnreadableReason = 3
	SupportLogUnreadableReasonUnopened  SupportLogUnreadableReason = 4
)

// The registry's fields' numbers.
const (
	supportLogFieldNumberCount            SupportLogFieldNumber = 1
	supportLogFieldNumberRelease          SupportLogFieldNumber = 2
	supportLogFieldNumberAutoSpawned      SupportLogFieldNumber = 3
	supportLogFieldNumberUptime           SupportLogFieldNumber = 4
	supportLogFieldNumberStopReason       SupportLogFieldNumber = 5
	supportLogFieldNumberSegments         SupportLogFieldNumber = 6
	supportLogFieldNumberRingBytes        SupportLogFieldNumber = 7
	supportLogFieldNumberPruneReason      SupportLogFieldNumber = 8
	supportLogFieldNumberUnreadableReason SupportLogFieldNumber = 9
	supportLogFieldNumberEntry            SupportLogFieldNumber = 10
	supportLogFieldNumberRun              SupportLogFieldNumber = 11
	supportLogFieldNumberAgent            SupportLogFieldNumber = 12
	supportLogFieldNumberRequest          SupportLogFieldNumber = 13
	supportLogFieldNumberTier             SupportLogFieldNumber = 14
	supportLogFieldNumberOutcome          SupportLogFieldNumber = 15
	supportLogFieldNumberRefusal          SupportLogFieldNumber = 16
	supportLogFieldNumberAttempts         SupportLogFieldNumber = 17
	supportLogFieldNumberWaited           SupportLogFieldNumber = 18
	supportLogFieldNumberBodyBytes        SupportLogFieldNumber = 19
	supportLogFieldNumberWithBundle       SupportLogFieldNumber = 20
	supportLogFieldNumberFiles            SupportLogFieldNumber = 21
	supportLogFieldNumberTainted          SupportLogFieldNumber = 22
	supportLogFieldNumberDecider          SupportLogFieldNumber = 23
	supportLogFieldNumberPostResult       SupportLogFieldNumber = 24
	supportLogFieldNumberStreamState      SupportLogFieldNumber = 25
	supportLogFieldNumberSidecar          SupportLogFieldNumber = 26
)

// count: a count, kept as its bucket.
func SupportLogFieldCount(count int64) SupportLogField {
	return supportLogCountField(supportLogFieldNumberCount, count)
}

// release: a version, kept only once it passes its format check.
func SupportLogFieldRelease(version string) SupportLogField {
	return supportLogVersionField(supportLogFieldNumberRelease, version)
}

// auto_spawned: true or false.
func SupportLogFieldAutoSpawned(value bool) SupportLogField {
	return supportLogBooleanField(supportLogFieldNumberAutoSpawned, value)
}

// uptime: a duration, kept as its bucket.
func SupportLogFieldUptime(duration time.Duration) SupportLogField {
	return supportLogDurationField(supportLogFieldNumberUptime, duration)
}

// stop_reason: one of stop_reason's values.
func SupportLogFieldStopReason(value SupportLogStopReason) SupportLogField {
	return supportLogEnumField(supportLogFieldNumberStopReason, uint32(value))
}

// segments: a count, kept as its bucket.
func SupportLogFieldSegments(count int64) SupportLogField {
	return supportLogCountField(supportLogFieldNumberSegments, count)
}

// ring_bytes: a size in bytes, kept as its class.
func SupportLogFieldRingBytes(byteCount int64) SupportLogField {
	return supportLogSizeField(supportLogFieldNumberRingBytes, byteCount)
}

// prune_reason: one of prune_reason's values.
func SupportLogFieldPruneReason(value SupportLogPruneReason) SupportLogField {
	return supportLogEnumField(supportLogFieldNumberPruneReason, uint32(value))
}

// unreadable_reason: one of unreadable_reason's values.
func SupportLogFieldUnreadableReason(value SupportLogUnreadableReason) SupportLogField {
	return supportLogEnumField(supportLogFieldNumberUnreadableReason, uint32(value))
}

// entry: an entry's id, kept only as an HMAC under the ring's key.
func SupportLogFieldEntry(id []byte) SupportLogField {
	return supportLogTokenField(supportLogFieldNumberEntry, id)
}

// run: a run's id, kept only as an HMAC under the ring's key.
func SupportLogFieldRun(id []byte) SupportLogField {
	return supportLogTokenField(supportLogFieldNumberRun, id)
}

// agent: an agent's id, kept only as an HMAC under the ring's key.
func SupportLogFieldAgent(id []byte) SupportLogField {
	return supportLogTokenField(supportLogFieldNumberAgent, id)
}

// request: a request's id, kept only as an HMAC under the ring's key.
func SupportLogFieldRequest(id []byte) SupportLogField {
	return supportLogTokenField(supportLogFieldNumberRequest, id)
}

// tier: one of tier's values.
func SupportLogFieldTier(value SupportLogTier) SupportLogField {
	return supportLogEnumField(supportLogFieldNumberTier, uint32(value))
}

// outcome: one of outcome's values.
func SupportLogFieldOutcome(value SupportLogOutcome) SupportLogField {
	return supportLogEnumField(supportLogFieldNumberOutcome, uint32(value))
}

// refusal: one of refusal's values.
func SupportLogFieldRefusal(value SupportLogRefusal) SupportLogField {
	return supportLogEnumField(supportLogFieldNumberRefusal, uint32(value))
}

// attempts: a count, kept as its bucket.
func SupportLogFieldAttempts(count int64) SupportLogField {
	return supportLogCountField(supportLogFieldNumberAttempts, count)
}

// waited: a duration, kept as its bucket.
func SupportLogFieldWaited(duration time.Duration) SupportLogField {
	return supportLogDurationField(supportLogFieldNumberWaited, duration)
}

// body_bytes: a size in bytes, kept as its class.
func SupportLogFieldBodyBytes(byteCount int64) SupportLogField {
	return supportLogSizeField(supportLogFieldNumberBodyBytes, byteCount)
}

// with_bundle: true or false.
func SupportLogFieldWithBundle(value bool) SupportLogField {
	return supportLogBooleanField(supportLogFieldNumberWithBundle, value)
}

// files: a count, kept as its bucket.
func SupportLogFieldFiles(count int64) SupportLogField {
	return supportLogCountField(supportLogFieldNumberFiles, count)
}

// tainted: true or false.
func SupportLogFieldTainted(value bool) SupportLogField {
	return supportLogBooleanField(supportLogFieldNumberTainted, value)
}

// decider: one of decider's values.
func SupportLogFieldDecider(value SupportLogDecider) SupportLogField {
	return supportLogEnumField(supportLogFieldNumberDecider, uint32(value))
}

// post_result: one of post_result's values.
func SupportLogFieldPostResult(value SupportLogPostResult) SupportLogField {
	return supportLogEnumField(supportLogFieldNumberPostResult, uint32(value))
}

// stream_state: one of stream_state's values.
func SupportLogFieldStreamState(value SupportLogStreamState) SupportLogField {
	return supportLogEnumField(supportLogFieldNumberStreamState, uint32(value))
}

// sidecar: a sidecar's id, kept only as an HMAC under the ring's key.
func SupportLogFieldSidecar(id []byte) SupportLogField {
	return supportLogTokenField(supportLogFieldNumberSidecar, id)
}

// The registry as tables, which Event and a bundle read.
var supportLogRegistry = &supportLogRegistryTable{
	version: 2,
	countBuckets: []supportLogBucket{
		{label: "0", max: 0, bounded: true},
		{label: "1", max: 1, bounded: true},
		{label: "2-9", max: 9, bounded: true},
		{label: "10-99", max: 99, bounded: true},
		{label: "100+"},
	},
	durationBuckets: []supportLogBucket{
		{label: "<10ms", max: 9, bounded: true},
		{label: "10-99ms", max: 99, bounded: true},
		{label: "100-999ms", max: 999, bounded: true},
		{label: "1-9s", max: 9999, bounded: true},
		{label: "10-59s", max: 59999, bounded: true},
		{label: "1-9m", max: 599999, bounded: true},
		{label: "10-59m", max: 3599999, bounded: true},
		{label: "1-23h", max: 86399999, bounded: true},
		{label: "1d+"},
	},
	sizeBuckets: []supportLogBucket{
		{label: "0", max: 0, bounded: true},
		{label: "<1KiB", max: 1023, bounded: true},
		{label: "1-63KiB", max: 65535, bounded: true},
		{label: "64KiB-1MiB", max: 1048575, bounded: true},
		{label: "1-15MiB", max: 16777215, bounded: true},
		{label: "16-255MiB", max: 268435455, bounded: true},
		{label: "256MiB+"},
	},
	components: map[SupportLogComponent]string{
		SupportLogComponentSupportLog: "support_log",
		SupportLogComponentDaemon:     "daemon",
		SupportLogComponentApp:        "app",
		SupportLogComponentSupport:    "support",
	},
	enums: map[string][]string{
		"decider":           {"none", "classifier", "person"},
		"outcome":           {"sent", "queued", "approval_pending", "declined", "not_sent"},
		"post_result":       {"accepted", "replayed", "client_error", "rate_limited", "server_error", "unreachable", "tls_failed", "timeout", "unauthorized"},
		"prune_reason":      {"age", "size"},
		"refusal":           {"disclosure_required", "secret_in_message", "hidden_text", "support_off", "rate_limited", "support_queue_full", "support_paused", "too_long", "not_text", "file_refused", "not_found", "no_host", "grant_required"},
		"stop_reason":       {"idle", "signal", "closed", "failed"},
		"stream_state":      {"opened", "closed", "failed"},
		"tier":              {"human", "released", "agent", "auto"},
		"unreadable_reason": {"truncated", "checksum", "malformed", "unopened"},
	},
	fields: map[SupportLogFieldNumber]*supportLogFieldRow{
		supportLogFieldNumberCount:            {name: "count", fieldType: supportLogFieldTypeCount},
		supportLogFieldNumberRelease:          {name: "release", fieldType: supportLogFieldTypeVersion},
		supportLogFieldNumberAutoSpawned:      {name: "auto_spawned", fieldType: supportLogFieldTypeBoolean},
		supportLogFieldNumberUptime:           {name: "uptime", fieldType: supportLogFieldTypeDuration},
		supportLogFieldNumberStopReason:       {name: "stop_reason", fieldType: supportLogFieldTypeEnum, enum: "stop_reason"},
		supportLogFieldNumberSegments:         {name: "segments", fieldType: supportLogFieldTypeCount},
		supportLogFieldNumberRingBytes:        {name: "ring_bytes", fieldType: supportLogFieldTypeSize},
		supportLogFieldNumberPruneReason:      {name: "prune_reason", fieldType: supportLogFieldTypeEnum, enum: "prune_reason"},
		supportLogFieldNumberUnreadableReason: {name: "unreadable_reason", fieldType: supportLogFieldTypeEnum, enum: "unreadable_reason"},
		supportLogFieldNumberEntry:            {name: "entry", fieldType: supportLogFieldTypeToken, object: "entry"},
		supportLogFieldNumberRun:              {name: "run", fieldType: supportLogFieldTypeToken, object: "run"},
		supportLogFieldNumberAgent:            {name: "agent", fieldType: supportLogFieldTypeToken, object: "agent"},
		supportLogFieldNumberRequest:          {name: "request", fieldType: supportLogFieldTypeToken, object: "request"},
		supportLogFieldNumberTier:             {name: "tier", fieldType: supportLogFieldTypeEnum, enum: "tier"},
		supportLogFieldNumberOutcome:          {name: "outcome", fieldType: supportLogFieldTypeEnum, enum: "outcome"},
		supportLogFieldNumberRefusal:          {name: "refusal", fieldType: supportLogFieldTypeEnum, enum: "refusal"},
		supportLogFieldNumberAttempts:         {name: "attempts", fieldType: supportLogFieldTypeCount},
		supportLogFieldNumberWaited:           {name: "waited", fieldType: supportLogFieldTypeDuration},
		supportLogFieldNumberBodyBytes:        {name: "body_bytes", fieldType: supportLogFieldTypeSize},
		supportLogFieldNumberWithBundle:       {name: "with_bundle", fieldType: supportLogFieldTypeBoolean},
		supportLogFieldNumberFiles:            {name: "files", fieldType: supportLogFieldTypeCount},
		supportLogFieldNumberTainted:          {name: "tainted", fieldType: supportLogFieldTypeBoolean},
		supportLogFieldNumberDecider:          {name: "decider", fieldType: supportLogFieldTypeEnum, enum: "decider"},
		supportLogFieldNumberPostResult:       {name: "post_result", fieldType: supportLogFieldTypeEnum, enum: "post_result"},
		supportLogFieldNumberStreamState:      {name: "stream_state", fieldType: supportLogFieldTypeEnum, enum: "stream_state"},
		supportLogFieldNumberSidecar:          {name: "sidecar", fieldType: supportLogFieldTypeToken, object: "sidecar"},
	},
	codes: map[SupportLogCode]*supportLogCodeRow{
		SupportLogCodeSupportLogOpened:            {component: SupportLogComponentSupportLog, name: "opened", severity: SupportLogSeverityInfo, fields: []SupportLogFieldNumber{supportLogFieldNumberSegments, supportLogFieldNumberRingBytes}},
		SupportLogCodeSupportLogEventsDropped:     {component: SupportLogComponentSupportLog, name: "events_dropped", severity: SupportLogSeverityDegraded, fields: []SupportLogFieldNumber{supportLogFieldNumberCount}},
		SupportLogCodeSupportLogSegmentPruned:     {component: SupportLogComponentSupportLog, name: "segment_pruned", severity: SupportLogSeverityInfo, fields: []SupportLogFieldNumber{supportLogFieldNumberPruneReason, supportLogFieldNumberSegments}},
		SupportLogCodeSupportLogSegmentUnreadable: {component: SupportLogComponentSupportLog, name: "segment_unreadable", severity: SupportLogSeverityDegraded, fields: []SupportLogFieldNumber{supportLogFieldNumberUnreadableReason}},
		SupportLogCodeSupportLogFieldRefused:      {component: SupportLogComponentSupportLog, name: "field_refused", severity: SupportLogSeverityDegraded, fields: []SupportLogFieldNumber{supportLogFieldNumberCount}},
		SupportLogCodeSupportLogWriteFailed:       {component: SupportLogComponentSupportLog, name: "write_failed", severity: SupportLogSeverityFailed, fields: []SupportLogFieldNumber{supportLogFieldNumberCount}},
		SupportLogCodeDaemonStarted:               {component: SupportLogComponentDaemon, name: "started", severity: SupportLogSeverityInfo, fields: []SupportLogFieldNumber{supportLogFieldNumberRelease, supportLogFieldNumberAutoSpawned}},
		SupportLogCodeDaemonStopped:               {component: SupportLogComponentDaemon, name: "stopped", severity: SupportLogSeverityInfo, fields: []SupportLogFieldNumber{supportLogFieldNumberStopReason, supportLogFieldNumberUptime}},
		SupportLogCodeAppStarted:                  {component: SupportLogComponentApp, name: "started", severity: SupportLogSeverityInfo, fields: []SupportLogFieldNumber{supportLogFieldNumberRelease}},
		SupportLogCodeAppStopped:                  {component: SupportLogComponentApp, name: "stopped", severity: SupportLogSeverityInfo, fields: []SupportLogFieldNumber{supportLogFieldNumberUptime}},
		SupportLogCodeSupportMessageRefused:       {component: SupportLogComponentSupport, name: "message_refused", severity: SupportLogSeverityDegraded, fields: []SupportLogFieldNumber{supportLogFieldNumberRefusal, supportLogFieldNumberTier, supportLogFieldNumberAgent, supportLogFieldNumberRun}},
		SupportLogCodeSupportMessageQueued:        {component: SupportLogComponentSupport, name: "message_queued", severity: SupportLogSeverityInfo, fields: []SupportLogFieldNumber{supportLogFieldNumberOutcome, supportLogFieldNumberTier, supportLogFieldNumberBodyBytes, supportLogFieldNumberWithBundle, supportLogFieldNumberFiles, supportLogFieldNumberTainted, supportLogFieldNumberDecider, supportLogFieldNumberAgent, supportLogFieldNumberRun, supportLogFieldNumberRequest}},
		SupportLogCodeSupportMessagePosted:        {component: SupportLogComponentSupport, name: "message_posted", severity: SupportLogSeverityInfo, fields: []SupportLogFieldNumber{supportLogFieldNumberPostResult, supportLogFieldNumberAttempts, supportLogFieldNumberWaited, supportLogFieldNumberEntry}},
		SupportLogCodeSupportPostFailed:           {component: SupportLogComponentSupport, name: "post_failed", severity: SupportLogSeverityDegraded, fields: []SupportLogFieldNumber{supportLogFieldNumberPostResult, supportLogFieldNumberAttempts}},
		SupportLogCodeSupportMessageGivenUp:       {component: SupportLogComponentSupport, name: "message_given_up", severity: SupportLogSeverityFailed, fields: []SupportLogFieldNumber{supportLogFieldNumberAttempts, supportLogFieldNumberWaited, supportLogFieldNumberEntry}},
		SupportLogCodeSupportStreamChanged:        {component: SupportLogComponentSupport, name: "stream_changed", severity: SupportLogSeverityInfo, fields: []SupportLogFieldNumber{supportLogFieldNumberStreamState, supportLogFieldNumberPostResult}},
		SupportLogCodeSupportEventReceived:        {component: SupportLogComponentSupport, name: "event_received", severity: SupportLogSeverityInfo, fields: []SupportLogFieldNumber{supportLogFieldNumberEntry}},
		SupportLogCodeSupportTokenFailed:          {component: SupportLogComponentSupport, name: "token_failed", severity: SupportLogSeverityDegraded, fields: []SupportLogFieldNumber{supportLogFieldNumberPostResult}},
	},
}
