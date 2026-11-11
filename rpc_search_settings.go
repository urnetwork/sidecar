// SEARCH's wire values (§6.5, §11.14's sizes and status rows; D-EVS-59, D-PROTO-21; DESIGN-DETAILS 11.2.9):
// a request's one body size and timeout, a reply's step and most steps, the widths pad's length may take,
// and Z4's caps on every other field, which keep a body's content where its pad always fits (QD-215,
// QD-693). They are the protocol's values, and changing one is a protocol change that no deployment makes on
// one side alone, so this one object holds them and its defaults stay here (QD-702). This side carries it as
// SidecarProtocolSettings.Search: SEARCH's envelope rules (rpc_search.go) and remote search's builders and
// parsers (search_remote_wire.go) read it there, the requester's and the indexer's alike.
//
// It links on every leg because SidecarProtocolSettings does; nothing on the sidecar_http or ios_extension
// legs reads it but SEARCH's envelope rules.

package sidecar

import (
	"time"
)

// What a SEARCH body holds and how large it is.
type SearchWireSettings struct {
	// A SEARCH request's one body size: 4,016 B, one envelope's whole body (§6.5), so a request is one
	// envelope of one length.
	RequestByteCount int
	// A SEARCH request's one timeout_ms: 10 s, whatever its caller asks, so the envelope has one length
	// (§6.5).
	Timeout time.Duration
	// A SEARCH_RESULT body's step: 16,384 B. A reply is exactly steps of these.
	StepByteCount int
	// The most steps a SEARCH_RESULT body holds: 4. v1 requesters ask 1.
	MaxStepCount int
	// The fewest and the most bytes pad's length varint takes: 2 and 3 (Z1, Z2). So every other field stops
	// at the body's size less 131 B (a tag, a two-byte length and 128 zeros), and a gap the two widths cannot
	// fill, 16,387 B, is stepped around (Z3, Z6).
	PadLengthMinByteCount int
	PadLengthMaxByteCount int
	// A request's query: at most 512 B (Z4; §16.10's 16 terms are the grammar's to count).
	QueryMaxByteCount int
	// A request's repos: at most 64 (Z4). A search over more goes in further requests (§11.14's order row).
	RepoMaxCount int
	// Every repo_id, ref_id, doc_key and signer a body carries: 16 B (Z4). A request's ref_id may also be
	// empty, naming the repo's default ref.
	IdByteCount int
	// A request's filters as encoded: at most 768 B (Z4; QD-215). A search with more stays on the device.
	FiltersMaxByteCount int
	// A reply's coverage rows: at most 64, one per repo named (Z4).
	CoverageMaxCount int
	// A coverage row's chain: at most 32 B (Z4; QD-693).
	ChainMaxByteCount int
	// A reply's hits: at most 20 (Z4, Z6).
	HitMaxCount int
	// A hit's locator: at most 512 B (Z4).
	LocatorMaxByteCount int
	// A near hit's correction: at most 256 B (Z4; QD-693).
	CorrectionMaxByteCount int
	// A hit's display fields: at most 8 (Z4).
	HitFieldMaxCount int
	// A display field's text: at most 256 B (Z4).
	HitFieldTextMaxByteCount int
	// A verified hit's snippet: at most 200 B (Z4).
	SnippetMaxByteCount int
}

// §6.5's and DESIGN-DETAILS 11.2.9's values, the only source of their defaults. A fresh value each call,
// sharing nothing mutable with any other.
func DefaultSearchWireSettings() *SearchWireSettings {
	return &SearchWireSettings{
		RequestByteCount:         MaxEnvelopeBodyByteCount,
		Timeout:                  10 * time.Second,
		StepByteCount:            16 * 1024,
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
}
