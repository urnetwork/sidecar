//go:build !ios_extension

// A completion ERASE (§11.12's push row; QD-1132; question erasure-completion-erase-evs-cannot-read-complete): where an
// erasure ends with no ERASE that destroys a key left to say complete, its eraser sends one more ERASE that says
// complete and names only a key an earlier ERASE of the erasure destroyed. It destroys nothing, and readers read it as
// completing the erasure alone, so the next CUT drops the erasure's entry from its ref's set. Erasers send one where an
// index rewrite finds nothing to rewrite (IndexEraser.Rewrite, record_erase.go) and where a mailbox erasure has no i/
// segment left to carry complete (mail_erase.go).
//
//	key      it names one key, one an ERASE of its erasure named first, before any other ERASE named it, and that no
//	         ERASE has named since: the oldest such. The newest ERASE naming that key is then the one that destroyed
//	         it, never a completion, so a racing runner's twin completion names the same key and meets the first, and a
//	         late copy's ERASE, which reopens the erasure, leaves the erasure keys that no completion took
//	answer   evs answers a completion it does not take NOTHING_TO_ERASE, as it answers an ERASE whose keys are gone,
//	         which counts done for any other ERASE. So an eraser reads evs's state after its completion and counts the
//	         erasure complete only where an ERASE of it now says so
//	evs      an ERASE's erasure id and complete byte ride its sealed metadata (QD-682), which evs cannot open, so a
//	         completion is a format-2 statement flagged COMPLETION beside ERASE alone (QD-1137). evs takes one naming
//	         no key a slot holds where the newest earlier ERASE naming each key, within its lookback, is no completion;
//	         readers take it as completing its erasure only where an earlier ERASE of that erasure named each key, and
//	         refuse one whose note says nothing complete. A format-1 repo has none
//
// Package-level functions are safe for concurrent use.

package sidecar

// The key a completion ERASE of erasureId names: see the file header's key row. erases is every committed ERASE the
// caller read of the repo's erasure ref, oldest first, each read by of as its erasure and the keys it names. False
// where no ERASE of the erasure named a key first that stands
// unnamed since.
func evsCompletionKeyOf[T any, K comparable](erases []T, erasureId Id, of func(erase T) (Id, []*K)) (*K, bool) {
	firstNamed := map[K]int{}
	lastNamed := map[K]int{}
	for index, erase := range erases {
		_, keys := of(erase)
		for _, key := range keys {
			if key == nil {
				continue
			}
			if _, named := firstNamed[*key]; !named {
				firstNamed[*key] = index
			}
			lastNamed[*key] = index
		}
	}
	for index, erase := range erases {
		eraseErasureId, keys := of(erase)
		if eraseErasureId != erasureId {
			continue
		}
		for _, key := range keys {
			if key != nil && firstNamed[*key] == index && lastNamed[*key] == index {
				copied := *key
				return &copied, true
			}
		}
	}
	return nil, false
}
