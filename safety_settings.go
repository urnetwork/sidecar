//go:build !ios_extension && !sidecar_http

// Automatic approvals' settings, DESIGN-COMPUTE §27's, which SAFE's tasks fill. Every limit, size, count, time,
// interval, threshold, retry or budget the component reads is a field here, its default set only in
// DefaultSafetySettings, protocol and format limits included; only identifiers stay constants (QD-702). The struct is
// created empty by the compute skeleton (CARCH-M11-01, CONTRACTS C-38), so no later task edits settings.go:
// SidecarSettings holds it, and DefaultSidecarSettings sets it from DefaultSafetySettings.
//
// SAFE-M13-01 sets every limit §27 names here at once, its own and those of the tasks after it, so no later task edits
// the file. Every number is positive: SidecarSettings.validate refuses a zero or a negative one, so none means
// unlimited or off.
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), declare
// an empty stand-in instead (sidecar_compute_leg.go).

package sidecar

import (
	"time"
)

// DESIGN-COMPUTE §27, automatic approvals: the tokenizer and classifier, scores, always-ask rules, limits and the
// digest.
type SafetySettings struct {
	// §27.6's windows. The most tokens the model reads at once, its two special tokens included, so 510 of text: 512,
	// the exported models' maximum input (question compute-plan-safe-window-specials, QD-1373). A format limit the
	// tokenizer, the engine helper and the app's host read alike.
	WindowTokenCount int
	// The tokens of text two neighboring windows share: 64, so an instruction split at a boundary that spans up to 65
	// tokens is whole in one of them. Must stay under WindowTokenCount less the two special tokens, or no window
	// advances and the windows are refused.
	WindowOverlapTokenCount int

	// §27.5's tokenizer: the release's SentencePiece vocabulary. The largest vocabulary file read, in bytes: 32 MiB,
	// several times mDeBERTa's 4.3 MB spm.model, which both Prompt Guard 2 models share. A larger one is refused before
	// it is parsed. Also the most a vocabulary file in the manifest may be.
	VocabularyMaxByteCount int
	// The most pieces a vocabulary may hold: 1,000,000, four times mDeBERTa's 250,101.
	VocabularyMaxPieceCount int
	// The longest piece, in bytes: 256, sixteen times SentencePiece's default of 16 characters at their longest, so the
	// encoder's lattice is bounded by it at every position of the text.
	VocabularyPieceMaxByteCount int
	// The longest key a rule of the vocabulary's precompiled character map may match, in bytes: 256, far past NFKC's
	// longest sequence. The normalizer looks no further at a position, so a character map that is not a tree, which
	// only a damaged file would hold, costs at most this much a position.
	CharsmapRuleMaxByteCount int
	// The longest text one Encode or Normalize reads, in bytes: 1 MiB, a long page's main text, some 560 windows. A
	// longer text is refused, so it is unscored and asks (§27.5's falling back), never cut.
	InputMaxByteCount int

	// §27.6's normalized view: Unicode's confusables.txt, pinned beside the vocabulary (question
	// compute-plan-safe-confusables-table, QD-1368). The largest table read, in bytes: 4 MiB, six times Unicode 16's
	// file. Also the most the manifest's table may be.
	ConfusablesMaxByteCount int
	// The most entries a table may hold: 65,536, ten times Unicode 16's 6,600.
	ConfusablesMaxEntryCount int
	// The most code points one entry's prototype may hold: 32; Unicode's longest, U+FDFA's, holds 18.
	ConfusablesTargetMaxCodePointCount int
	// How many times its input's size a normalized view may grow to, at any step, before the text is refused as
	// unscorable, which asks: 16. NFKC grows a text at most 11 times (U+FDFA), and the skeletons a few.
	NormalizeGrowthMaxFactor int
	// How many passes of the view's steps the normalizer runs to reach the view that its steps leave unchanged: 4. Two
	// reach it for any text Unicode's own data gives; a text still changing after these is refused as unscorable.
	NormalizeMaxPassCount int

	// §27.6's threshold. Where the release's calibration starts, in basis points: 2,000, a probability of 0.20, well
	// under the model's own 5,000, so doubt asks. The threshold a device decides by is only the one the verified
	// manifest pins (Q-SAFE-6); this is the bench's (SAFE-M13-13).
	DefaultThresholdBasisPoints int
	// The highest threshold a manifest may pin, in basis points: 5,000, the model's own decision point. A manifest
	// pinning more is refused whole.
	MaxThresholdBasisPoints int

	// §27.5's engine. How long one classification may take before it answers unavailable, which asks: 10 seconds. A
	// call to the engine helper past it ends that helper, and the next call starts another.
	DecisionTimeout time.Duration
	// How long the engine helper stays once no classification runs: 10 minutes, then it is ended, and the next
	// tainted run's first classification starts it again.
	EngineIdleTimeout time.Duration
	// How long loading the runtime and the model into a helper may take: 2 minutes, the 86M at int8, some 300 MB, read
	// from a slow disk. Past it the helper is ended and the classification answers unavailable.
	EngineLoadTimeout time.Duration
	// The threads one classification may compute with in the helper, ONNX Runtime's intra-op threads: 4, so a window
	// scores quickly while a desktop's other cores stay free.
	EngineIntraOpThreadCount int
	// The most windows one call to the helper carries: 16, some 3 seconds of the 86M on a desktop's CPU, well within
	// DecisionTimeout; a longer text's windows go in several calls. A format limit the helper reads too.
	EngineWindowMaxCount int

	// §27.5's shipping: the classifier's entries in the signed release, safety_manifest.json. The largest manifest
	// parsed, in bytes: 1 MiB, room for many releases' worth of entries.
	ManifestMaxByteCount int
	// The largest model file the manifest may pin, in bytes: 2 GiB, past the 86M at F32 (about 1.1 GB), so a typo cannot
	// pin an unbounded download.
	ModelMaxByteCount int64
	// The largest runtime library the manifest may pin, in bytes: 512 MiB, many times ONNX Runtime's CPU build.
	RuntimeMaxByteCount int64
	// How long one file's download may take: 30 minutes, the 86M on a link under 2 megabits a second. Past it the fetch
	// stops, its part kept for the next.
	FetchTimeout time.Duration
	// The redirects one file's request may follow: 3, a release asset's redirect to its storage host. Each must be
	// https, to the url's own host or one under FetchRedirectHostSuffixes.
	FetchRedirectMaxCount int
	// The hosts a file's request may be redirected to besides the url's own, each a domain matching itself and every
	// name under it: GitHub's and its release assets' storage, where the release's assets are served on 2026-11-27.
	FetchRedirectHostSuffixes []string
	// The room a fetch leaves on the volume past what it writes, as a fraction of the file: 0.1.
	FetchFreeSpaceMarginFraction float64

	// §27.8's limits. Automatic approvals a run may take: 10, a run's ordinary fetches and writes (Q-SAFE-8, QD-1349).
	RunAutoMaxCount int
	// Automatic approvals a device may make in a minute, across its runs: 3 (question compute-plan-safe-minute-limit,
	// QD-1372).
	MinuteAutoMaxCount int
	// Automatic approvals a device may make in a UTC day: 50, a busy person's day.
	DayAutoMaxCount int

	// §27.7's rules. How far back the member's record makes a destination known, in days: 90.
	KnownDestinationDays int
	// The budget past which a launch asks, rule amount, in nano-USD a day or a run: $1.
	AmountRuleNanoUsd int64
	// The shortest span of the person's own words an action may copy unscored, in characters of the normalized view: 32,
	// a sentence rather than a word (question compute-plan-safe-copied-span, QD-1369). A shorter copy is scored as any
	// other text.
	CopiedSpanMinCharCount int

	// §27.9's digest. The local hour its notification comes at unless the person picks another: 18.
	DigestHour int

	// §27.6's scoring off the turn's path (SAFE-M13-04). The inputs waiting to be scored on a device: 256. An input the
	// queue drops is unscored, which asks at decision time, never clean.
	ScoreQueueMaxCount int
	// The inputs one run's memory keeps scores for: 1,024, a long run's pages, mail and results. Past it the oldest is
	// evicted and the run no longer holds every input that tainted it, so each later decision in it asks
	// (inputs_unknown).
	RunInputMaxCount int
}

// The component's defaults, the only place one is set.
func DefaultSafetySettings() *SafetySettings {
	return &SafetySettings{
		WindowTokenCount:                   512,
		WindowOverlapTokenCount:            64,
		VocabularyMaxByteCount:             32 * 1024 * 1024,
		VocabularyMaxPieceCount:            1000 * 1000,
		VocabularyPieceMaxByteCount:        256,
		CharsmapRuleMaxByteCount:           256,
		InputMaxByteCount:                  1024 * 1024,
		ConfusablesMaxByteCount:            4 * 1024 * 1024,
		ConfusablesMaxEntryCount:           64 * 1024,
		ConfusablesTargetMaxCodePointCount: 32,
		NormalizeGrowthMaxFactor:           16,
		NormalizeMaxPassCount:              4,
		DefaultThresholdBasisPoints:        2000,
		MaxThresholdBasisPoints:            5000,
		DecisionTimeout:                    10 * time.Second,
		EngineIdleTimeout:                  10 * time.Minute,
		EngineLoadTimeout:                  2 * time.Minute,
		EngineIntraOpThreadCount:           4,
		EngineWindowMaxCount:               16,
		ManifestMaxByteCount:               1024 * 1024,
		ModelMaxByteCount:                  2 * 1024 * 1024 * 1024,
		RuntimeMaxByteCount:                512 * 1024 * 1024,
		FetchTimeout:                       30 * time.Minute,
		FetchRedirectMaxCount:              3,
		FetchRedirectHostSuffixes:          []string{"github.com", "githubusercontent.com"},
		FetchFreeSpaceMarginFraction:       0.1,
		RunAutoMaxCount:                    10,
		MinuteAutoMaxCount:                 3,
		DayAutoMaxCount:                    50,
		KnownDestinationDays:               90,
		AmountRuleNanoUsd:                  1000 * 1000 * 1000,
		CopiedSpanMinCharCount:             32,
		DigestHour:                         18,
		ScoreQueueMaxCount:                 256,
		RunInputMaxCount:                   1024,
	}
}
