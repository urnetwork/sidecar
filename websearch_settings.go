//go:build !ios_extension && !sidecar_http

// Web search's settings, DESIGN-COMPUTE §21's, which SRCH's tasks fill. Every limit, size, count, time, interval,
// threshold, retry or budget the component reads is a field here, its default set only in DefaultWebSearchSettings,
// protocol and format limits included; only identifiers stay constants (QD-702). The struct is created empty by the
// compute skeleton (CARCH-M11-01, CONTRACTS C-38), so no later task edits settings.go: SidecarSettings holds it, and
// DefaultSidecarSettings sets it from DefaultWebSearchSettings. SRCH-M13-01 fills it whole, so the client, the tool
// and the charge check only read it (SRCH-M13-02, -10, -12).
//
// The authorization's window and the seal's sizes are a format both ends share: the device checks what searchsigner
// signs to the same offsets, so the signer's settings carry these fields rather than a second copy of their defaults.
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), declare
// an empty stand-in instead (sidecar_compute_leg.go).

package sidecar

import (
	"time"
)

// DESIGN-COMPUTE §21, web search: the x402 client, the tool and its outcomes.
type WebSearchSettings struct {
	// The grain an authorization is timed to: a minute (§21.5, §9.7). Its window and its charge both take the admission's
	// minute, never a clock's finer time.
	AuthorizationGrain time.Duration
	// The window's offsets from the minute's start (§21.5): valid_after 60 s before it and valid_before 120 s after it,
	// at most 3 minutes, inside the offer's 300 s. A format both ends share.
	WindowBefore time.Duration
	WindowAfter  time.Duration
	// How far an authorization's minute may stand from this device's clock across the broker's round trip and still be
	// the admission's: 2 minutes. Past it the device refuses the authorization before paying.
	WindowSkew time.Duration

	// The device's draws (§21.5): a 32-byte nonce, which EIP-3009's bytes32 takes exactly, and a 16-byte request id.
	NonceByteCount     int
	RequestIdByteCount int
	// Attempts per request id: 3, each a new 402 after the gateway lost its payee, with a new nonce and its own hold.
	AttemptMaxCount int
	// How often a lost answer from the broker is asked again with the same request id, attempt and sealed bytes: twice.
	BrokerRetryCount int

	// The gateway's answer to a paid search (§21.5): within 30 s of the paid retry leaving, else the outcome is
	// timeout, and at most 2 MiB, else provider_error.
	AnswerTimeout      time.Duration
	AnswerMaxByteCount int
	// The most bytes a 402's challenge may hold, header or body: 64 KiB.
	ChallengeMaxByteCount int
	// The least maxTimeoutSeconds an offer may give, the window's reach: 120 s (§21.5).
	OfferMinTimeout time.Duration
	// The header the paid retry carries its x402 v2 payload in: PAYMENT-SIGNATURE, as the gateway's v2 challenge and
	// Stripe's purl use it, until G-SRCH-parallel's load test says otherwise (§21.3, §21.11).
	PaymentHeader string
	// The fixed request headers' values (§21.5): the body's media type, the encodings the device takes and the product
	// a User-Agent names before its version. A gzip answer is still read, within AnswerMaxByteCount once decoded.
	ContentType    string
	AcceptEncoding string
	UserAgent      string

	// A device's pace (§21.9): at most 25 searches a minute, each two requests, against the gateway's 60 an address.
	DevicePaceCount  int
	DevicePaceWindow time.Duration
	// A 429's Retry-After waited and retried through the same exit, never another (§21.9): at most twice a request,
	// each wait at most 60 s; past either the outcome is refused.
	RateLimitedRetryCount int
	RateLimitedWaitMax    time.Duration

	// The gateway's documented fields' limits (§21.3): one to five search_queries of at most 200 characters, and an
	// objective of at most 5,000 characters, which the tool's own schema narrows to 1,000.
	QueryMinCount                  int
	QueryMaxCount                  int
	QueryMaxCharacterCount         int
	ObjectiveMaxCharacterCount     int
	ToolObjectiveMaxCharacterCount int

	// The tool's limits (§21.6): 50 searches a run and 30 a minute an agent, set per agent; a run's count forgotten once
	// it has searched nothing for a day.
	RunSearchMaxCount     int
	AgentSearchMaxCount   int
	AgentSearchWindow     time.Duration
	RunCountIdleRetention time.Duration
	// What the model reads of results (§21.6): each result's excerpts cut at 3,000 characters, the whole at 20,000.
	ResultExcerptMaxCharacterCount int
	ExcerptTotalMaxCharacterCount  int
	// What the UI's details show of a result: its first excerpt, cut at 500 characters.
	DetailsExcerptMaxCharacterCount int

	// The outcomes a device has not reported ride its next authorization, or this daily report if it searches no more
	// (§21.8): once a UTC day, the first try at the interval and a failed one again after the retry interval.
	OutcomesReportInterval      time.Duration
	OutcomesReportRetryInterval time.Duration
	// The outcome log's file: at most 4 KiB.
	OutcomeLogMaxByteCount int

	// The device's check of kind-6 charges (§21.8's Check, SRCH-M13-12): hourly, over the last 72 hours.
	ChargeCheckInterval time.Duration
	ChargeCheckReach    time.Duration

	// §9.6's price rule as the device checks an offer against the catalog (§21.8): the compute markup, 6/5, and a
	// search's retail step, $0.0001, the values the broker's ledger settings carry. A USDC unit is 1,000 nano-USD, its 6
	// decimals.
	MarkupNumerator        int64
	MarkupDenominator      int64
	SearchPriceStepNanoUsd int64
	AssetUnitNanoUsd       int64

	// The policy's search line, as SRCH decodes it strictly (websearch_policy.go): its JSON at most 8 KiB, a host of at
	// most 253 bytes and a network name of at most 41.
	PolicyLineMaxByteCount int
	PolicyHostMaxByteCount int
	NetworkMaxByteCount    int
}

// The component's defaults, the only place one is set.
func DefaultWebSearchSettings() *WebSearchSettings {
	return &WebSearchSettings{
		AuthorizationGrain: time.Minute,
		WindowBefore:       60 * time.Second,
		WindowAfter:        120 * time.Second,
		WindowSkew:         2 * time.Minute,

		NonceByteCount:     32,
		RequestIdByteCount: 16,
		AttemptMaxCount:    3,
		BrokerRetryCount:   2,

		AnswerTimeout:         30 * time.Second,
		AnswerMaxByteCount:    2 * 1024 * 1024,
		ChallengeMaxByteCount: 64 * 1024,
		OfferMinTimeout:       120 * time.Second,
		PaymentHeader:         "PAYMENT-SIGNATURE",
		ContentType:           "application/json",
		AcceptEncoding:        "identity",
		UserAgent:             "ur",

		DevicePaceCount:       25,
		DevicePaceWindow:      time.Minute,
		RateLimitedRetryCount: 2,
		RateLimitedWaitMax:    60 * time.Second,

		QueryMinCount:                  1,
		QueryMaxCount:                  5,
		QueryMaxCharacterCount:         200,
		ObjectiveMaxCharacterCount:     5000,
		ToolObjectiveMaxCharacterCount: 1000,

		RunSearchMaxCount:               50,
		AgentSearchMaxCount:             30,
		AgentSearchWindow:               time.Minute,
		RunCountIdleRetention:           24 * time.Hour,
		ResultExcerptMaxCharacterCount:  3000,
		ExcerptTotalMaxCharacterCount:   20000,
		DetailsExcerptMaxCharacterCount: 500,

		OutcomesReportInterval:      24 * time.Hour,
		OutcomesReportRetryInterval: time.Hour,
		OutcomeLogMaxByteCount:      4 * 1024,

		ChargeCheckInterval: time.Hour,
		ChargeCheckReach:    72 * time.Hour,

		MarkupNumerator:        6,
		MarkupDenominator:      5,
		SearchPriceStepNanoUsd: 100_000,
		AssetUnitNanoUsd:       1_000,

		PolicyLineMaxByteCount: 8 * 1024,
		PolicyHostMaxByteCount: 253,
		NetworkMaxByteCount:    41,
	}
}
