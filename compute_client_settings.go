//go:build !ios_extension && !sidecar_http

// The compute client's settings, DESIGN-COMPUTE §9's, which BAL's tasks fill. Every limit, size, count, time, interval,
// threshold, retry or budget the component reads is a field here, its default set only in DefaultComputeClientSettings,
// protocol and format limits included; only identifiers stay constants (QD-702). The struct is created empty by the
// compute skeleton (CARCH-M11-01, CONTRACTS C-38), so no later task edits settings.go: SidecarSettings holds it, and
// DefaultSidecarSettings sets it from DefaultComputeClientSettings.
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), declare
// an empty stand-in instead (sidecar_compute_leg.go).

package sidecar

import (
	"time"
)

// DESIGN-COMPUTE §9, the device's compute client: the balance, purchases, auto-renew and the spend view
// (BAL-M12-17).
type ComputeClientSettings struct {
	// How often the client reads the balance while no client generation holds the compute push topic, the path
	// compute-plan-compute-low-delivery settles (QD-1238): 1 hour. While a generation holds it, each hint and resync
	// prompts a read instead, so a device online with push never polls. Non-positive turns the poll off, leaving
	// hints, refused holds and the surfaces' own reads.
	BalancePollInterval time.Duration
	// The least time between two reads of the balance that a hint, a resync or a refused hold asks for: 5 s, so a
	// burst of refusals, or a hint racing one, reads once. A surface's own Balance call is never held back.
	BalanceReadMinInterval time.Duration
	// A failed read's first retry, then twice as long each time up to BalanceRetryMaxInterval: 30 s to 15 min.
	BalanceRetryFirstInterval time.Duration
	BalanceRetryMaxInterval   time.Duration
	// How many times one asked-for read is retried before it waits for the next ask: 6, past 15 minutes of doubling
	// from 30 s. Zero retries none.
	BalanceRetryMaxCount int
	// One call to api's compute routes, when its caller set no shorter bound: 30 s.
	RequestTimeout time.Duration

	// §9.5's Stripe packs, in credits, a credit one US dollar: 10, 25, 50, 100, 250 and 500. None of 5, on which
	// Stripe's fees take 9% (§10.6). A format of what Checkout sells, which api holds too.
	StripePackCredits []int64
	// §9.8's monthly plan, in credits a month: 10, 25, 50, 100 or 250.
	MonthlyPlanCredits []int64
	// The hosts a Checkout url may name, each over https: Stripe Checkout's own, checkout.stripe.com. A url naming
	// any other is refused before any surface opens it, so an answer api did not mean cannot send a person's card
	// elsewhere.
	CheckoutHosts []string
	// The longest Checkout url the client takes, in bytes: 2 KiB, past Stripe's own urls.
	CheckoutUrlMaxByteCount int

	// A promotion code (§9.11): 8 to 32 letters and digits. A format limit, which api's redemption holds too.
	PromoCodeMinCharacterCount int
	PromoCodeMaxCharacterCount int

	// The spend view's recent window (§9.13, Q-BAL-8): today so far and the 6 UTC days before it, 7.
	SpendDayCount int
	// A label is shown only within this many characters, else as unknown: 96, the bound §9.13 and §6.3 set for a
	// label no signed source vouches for, which holds a signed one too, so no answer reaches a model unbounded.
	LabelMaxCharacterCount int
	// An agent's name as §20.5's grammar bounds it, [a-z0-9][a-z0-9-]{0,47}: 48 bytes. The format is SKILL's, whose
	// settings take this default once SKILL fills them; until then the labeler holds a card's name to it here.
	AgentNameMaxByteCount int
	// The charges route's page, in rows, which api may answer fewer of: 100.
	ChargesPageRowCount int
	// The longest page cursor the client sends back, in bytes: 256, an opaque position api writes.
	CursorMaxByteCount int
	// The most rows one answer of the charges, statement or spend routes may hold before the client refuses it
	// whole: 10,000, past a month's day rows for a busy network, so a broken answer cannot fill memory.
	AnswerMaxRowCount int
}

// The component's defaults, the only place one is set.
func DefaultComputeClientSettings() *ComputeClientSettings {
	return &ComputeClientSettings{
		BalancePollInterval:        1 * time.Hour,
		BalanceReadMinInterval:     5 * time.Second,
		BalanceRetryFirstInterval:  30 * time.Second,
		BalanceRetryMaxInterval:    15 * time.Minute,
		BalanceRetryMaxCount:       6,
		RequestTimeout:             30 * time.Second,
		StripePackCredits:          []int64{10, 25, 50, 100, 250, 500},
		MonthlyPlanCredits:         []int64{10, 25, 50, 100, 250},
		CheckoutHosts:              []string{"checkout.stripe.com"},
		CheckoutUrlMaxByteCount:    2 * 1024,
		PromoCodeMinCharacterCount: 8,
		PromoCodeMaxCharacterCount: 32,
		SpendDayCount:              7,
		LabelMaxCharacterCount:     96,
		AgentNameMaxByteCount:      48,
		ChargesPageRowCount:        100,
		CursorMaxByteCount:         256,
		AnswerMaxRowCount:          10000,
	}
}
