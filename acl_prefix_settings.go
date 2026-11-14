// Client-checked prefix write rules' settings (DESIGN-DETAILS 16.2.11; QD-212, QD-702): every limit of a
// RepoPrefixRules and of the sets it seals is a field here, its default set only in DefaultAclPrefixSettings, and none
// is a constant. The first five are format limits every verifier of the log or of a set holds alike, so changing one
// is a protocol change no deployment makes on one side alone: the two id-level limits, which api, every gate and every
// device judge a RepoPrefixRules entry by (16.2.2), then what makes an opened set void or a pending one void
// (ACL-M6-04's acl_prefix.go). The rest arrive with the tasks that read them: WalkBackVersionCount and AlarmInterval
// with EVS1-M6-04's readers, and the repair's four with EVS1-M6-05.
//
// The statement rules read DefaultAclPrefixSettings(), as they read DefaultAclAccessLogSettings(); threading each
// side's own instance through them is the review phase's settings sweep (QD-706).
//
// The sealed form is config_seal.go's: u64be(g), a 24 B nonce, the plaintext padded to a multiple of 256 B, and the
// AEAD's 16 B tag. Those sizes are that format's and a cipher's, so they stay its constants. A rule's path is at most
// a token path's 32 components (§11.6), which evs_token.go's EvsTokenPathMaxLength holds for every evs format.
//
// On every leg, the ios_extension and sidecar_http legs' included: acl_statement_repo.go reads it. No key is created,
// derived or unwrapped here, so nothing calls testHookSecret.

package sidecar

import (
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// A RepoPrefixRules' limits that every verifier of the log holds alike (DESIGN-DETAILS 16.2.11).
type AclPrefixSettings struct {
	// The longest RepoPrefixRules.sealed_rules, in bytes: 65,536 (64 KiB), which with config_seal's 48 B of framing
	// holds 255 blocks of 256 B of padded rules, room for RuleMaxCount rules of deep paths. An id-level rule: a longer
	// body is refused at api and by every reader. Non-positive takes no set.
	SealedMaxByteCount int
	// The most rule sets one repo's rows hold, for the repo's life: 256. A row is never removed, since pushes pinned
	// in its span are judged by it, so the cap bounds a repo's share of §8.8's 4 MiB of rows at about 6 KiB; a team
	// that would pass it moves to a new repo (D-ACL-11). An id-level rule: the next set is refused, naming this limit.
	// Non-positive takes no set.
	SetMaxCount int
	// The most rules one opened set holds, the standing admins' among them: 256 (16.2.2's opened row). A set past it
	// is void at every reader, and no design device seals one. Non-positive opens no set with a rule, so every set but
	// the empty one is void.
	RuleMaxCount int
	// How long after the entry that carries a set its generation's GenRotate may be signed: 1 h (16.2.2's void row;
	// DESIGN-DETAILS 12.2.3's readers' half, on the recommendation of details-amend-2-late-generation). A set sealed to
	// a generation signed later than this is void, whenever its reader comes to hold that generation, so a generation
	// claimed after a reader voided its set as unformed changes no verdict. An honest filer seals to a generation it
	// holds, which gkm took within 10 min of its own clock, so the grace sits well above the two servers' clocks.
	// Non-positive voids a set whose generation was signed at all after its entry.
	GenerationFormGrace time.Duration
	// How far past GenerationFormGrace, in the log's time after a set's entry, a reader waits before it voids a pending
	// set whose generation its whole read of gkm's generation listing does not name: 30 min (16.2.3), above gkm's
	// 10 min and api's and gkm's 20 min clock bounds, so a generation claimed after the void is signed past the grace
	// and voids the set at every reader that gains it. Non-positive waits the grace alone.
	PendingVoidMargin time.Duration
}

// DESIGN-DETAILS 16.2.11's values. A fresh value each call.
func DefaultAclPrefixSettings() *AclPrefixSettings {
	return &AclPrefixSettings{
		SealedMaxByteCount:  64 * 1024,
		SetMaxCount:         256,
		RuleMaxCount:        256,
		GenerationFormGrace: 1 * time.Hour,
		PendingVoidMargin:   30 * time.Minute,
	}
}

// Whether a sealed_rules of byteCount bytes has config_seal's form and fits: its 48 B of framing around a positive
// multiple of 256 B of padded plaintext, at most SealedMaxByteCount in all (DESIGN-DETAILS 16.2.2's body row). Only the
// length is read: no verifier opens the body to judge the statement.
func (self *AclPrefixSettings) SealedByteCountFits(byteCount int) bool {
	framing := configSealGenerationByteCount + chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead
	padded := byteCount - framing
	return 0 < padded && padded%configSealPadByteCount == 0 && byteCount <= self.SealedMaxByteCount
}

// Whether a repo whose rows hold setCount sets takes one more: fewer than SetMaxCount (DESIGN-DETAILS 16.2.2's count
// row).
func (self *AclPrefixSettings) SetFits(setCount int) bool {
	return setCount < self.SetMaxCount
}

// Whether a set's generation, signed at signedMs, came later than GenerationFormGrace after the entry that carries the
// set, at entryMs: the late generation that voids it (16.2.2). A difference taken only where it is positive, as
// unsigned, so no time can wrap it.
func (self *AclPrefixSettings) generationLate(signedMs int64, entryMs int64) bool {
	if signedMs <= entryMs {
		return false
	}
	return uint64(max(0, self.GenerationFormGrace.Milliseconds())) < uint64(signedMs-entryMs)
}

// Whether the log's time at timeMs is past a pending set's entry at entryMs by more than GenerationFormGrace plus
// PendingVoidMargin, when a whole read of gkm that names no such generation voids it (16.2.3).
func (self *AclPrefixSettings) pendingVoidDue(timeMs int64, entryMs int64) bool {
	if timeMs <= entryMs {
		return false
	}
	waitMs := max(0, self.GenerationFormGrace.Milliseconds()) + max(0, self.PendingVoidMargin.Milliseconds())
	return uint64(waitMs) < uint64(timeMs-entryMs)
}
