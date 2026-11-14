// Client-checked prefix write rules' settings (DESIGN-DETAILS 16.2.11; QD-212, QD-702): every limit of a
// RepoPrefixRules and of the sets it seals is a field here, its default set only in DefaultAclPrefixSettings, and none
// is a constant. The fields this file holds are the two id-level limits, which api, every gate and every device judge
// a RepoPrefixRules entry by (16.2.2), so changing one is a protocol change no deployment makes on one side alone. The
// rest arrive with the tasks that read them: RuleMaxCount, GenerationFormGrace and PendingVoidMargin with ACL-M6-04's
// opened sets, WalkBackVersionCount and AlarmInterval with EVS1-M6-04's readers, and the repair's four with
// EVS1-M6-05.
//
// The statement rules read DefaultAclPrefixSettings(), as they read DefaultAclAccessLogSettings(); threading each
// side's own instance through them is the review phase's settings sweep (QD-706).
//
// The sealed form is config_seal.go's: u64be(g), a 24 B nonce, the plaintext padded to a multiple of 256 B, and the
// AEAD's 16 B tag. Those sizes are that format's and a cipher's, so they stay its constants.
//
// On every leg, the ios_extension and sidecar_http legs' included: acl_statement_repo.go reads it. No key is created,
// derived or unwrapped here, so nothing calls testHookSecret.

package sidecar

import (
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
}

// DESIGN-DETAILS 16.2.11's values. A fresh value each call.
func DefaultAclPrefixSettings() *AclPrefixSettings {
	return &AclPrefixSettings{
		SealedMaxByteCount: 64 * 1024,
		SetMaxCount:        256,
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
