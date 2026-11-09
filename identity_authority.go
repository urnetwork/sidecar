// SidecarAuthority (CORE-M2-01, C-10): §7.9's verified state as §5's device acts read it. Every M2-M3 task of §5
// reads the log through this one seam, never ConfigState directly, so each starts on sidecartest.FakeAuthority before
// TEAM's ConfigClient lands and then runs on TEAM-M2-10's adapter over ConfigState (config_authority_seam.go), with
// nothing of CORE's replaced. Its methods are C-10's union: what an admission, a device list, consent, a member's
// recovery binding, the presence rule, a signer's live presence keys, a compromise cascade, a loss time's proposed
// position and each applied entry mean are §7.9's and §8.5's single definitions, behind this seam. CORE's acts sign
// and post; they never re-derive a rule (C-01).
//
// A Sidecar holds at most one authority, which its host installs once the network's ConfigClient follows the log
// (InstallAuthority), and every gate in identity_admission.go asks it. With none installed nothing is admitted, so a
// sidecar whose log is not followed yet gets no peer, group, wrap or grant (§5.6).
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"crypto/sha256"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One statement as an act built it, before it is signed: what §7.9's presence row judges.
type SidecarStatement struct {
	// Who signs it: this sidecar, by its identity key.
	SignerId Id
	Type     bridge.SignedType
	// The statement's bytes, its StatementHeader included, exactly as they will be signed.
	Body []byte
}

// A statement's §6.9 signed bytes' SHA-256, which an act's tree hashes as its leaf (§7.9's presence row).
func (self *SidecarStatement) digest() [sha256.Size]byte {
	purpose, _ := sidecarIdentitySignedPurpose(self.Type)
	return bridge.SignedBytesSha256(purpose, self.Type, self.Body)
}

// One of §7.9's Recovery windows as an entry moved it (TEAM-M2-05's verdict): the same for every device that applies
// the entry, carrying no alarm, which each device derives from its own application times (CORE-M2-03).
type SidecarRecoveryWindow struct {
	// The AuthorityProposal's 32-byte id.
	ProposalId []byte
	// pending: open from Start; activated: an ApiTick ended it in the proposal's favor; vetoed: a RecoveryVeto
	// closed it; expired: its not_after passed.
	State string
	// p: the entry of the window's newest recovery-key signature, which a late recovery cosign moves.
	Start uint64
	// The member whose recovery key signed it, or whose restored binding admits.
	MemberId Id
	// A restored binding's admission: the device it admits. Nil for an authority statement.
	SidecarId *Id
	// Whether a recovery-key signature opened it, else a restored binding's admission (§5.6's signers row).
	RecoverySigned bool
}

// The states SidecarRecoveryWindow.State takes.
const (
	SidecarRecoveryWindowPending   = "pending"
	SidecarRecoveryWindowActivated = "activated"
	SidecarRecoveryWindowVetoed    = "vetoed"
	SidecarRecoveryWindowExpired   = "expired"
)

// A member's recovery binding an entry's cascade voided (§7.9's cascade), at which §5.6 alarms and §5.9 re-seals.
type SidecarVoidedBinding struct {
	MemberId Id
	// The voided binding's key hash, MemberRow.recovery_key_sha256's form.
	KeySha256 []byte
	// The sidecar in P that signed it.
	Signer []byte
}

// One statement that took effect at an entry, with every signer it took effect with: a statement on its own entry; a
// proposed statement at the entry of its k-th cosign, with the proposal's and each cosign's signers; a recovery
// window's statement at the ApiTick that activated it (§7.9's proposal, completion and Recovery rows).
type SidecarAuthorityEffect struct {
	Type bridge.SignedType
	// The statement's bytes, its StatementHeader included.
	Body    []byte
	Signers []ConfigSigner
}

// One applied entry, as AddEntryCallback reports it, with its verdict.
type SidecarAuthorityEntry struct {
	// (n, A_n) after the entry.
	Pin *bridge.AuthPin
	// api's time for the entry, ms since the epoch: server-asserted, which no device compares with its own clock
	// (§7.9's time row).
	TimeMs int64
	// bridge.AuthEntryKind's value: BASE, STATEMENT or TICK.
	Kind uint32
	// A STATEMENT's Signed as carried, and its signers as §6.9 reads them. Nil for a BASE or a TICK.
	Signed  *bridge.Signed
	Signers []ConfigSigner
	// Whether the statement applied. A verifier that refuses an entry api sequenced forks there (§6.4), and the
	// entry carries no verdict.
	Applied bool
	// What took effect at the entry, in order: what §5.6's alarms read, so a proposal's completion and a window's
	// activation alarm where they take effect, not where they were proposed.
	Effects []*SidecarAuthorityEffect
	// The Recovery windows the entry opened, moved or closed.
	Windows []SidecarRecoveryWindow
	// The recovery bindings the entry's cascade voided.
	VoidedBindings []SidecarVoidedBinding
	// The live admissions after the entry and config_admissions' cap (§7.10), 0 for none.
	AdmissionCount int
	AdmissionCap   int
	// The AdminSet's members after the entry, whose devices admissions_near_cap alarms.
	AdminMemberIds []Id
}

// Called once per applied entry, in log order, on the follower's goroutine. It must not block or call back into the
// authority's writer.
type SidecarAuthorityEntryFunction func(entry *SidecarAuthorityEntry)

// §7.9's state as a device act reads it (C-10). TEAM-M2-10 implements it over ConfigState; sidecartest.FakeAuthority
// fakes it. Safe for concurrent use. A sidecar_id or member_id the state does not hold answers nil, false or empty,
// never an error.
type SidecarAuthority interface {
	// The newest verified (n, A_n): ConfigState.Pin.
	Pin() *bridge.AuthPin
	// The sidecar's admission row, revoked tombstones included: ConfigState.Sidecar. Nil for one no SidecarAdmit
	// names.
	Admission(sidecarId Id) *AclSidecar
	// Every admitted sidecar whose untagged admission names memberId, revoked ones included, in id order: what
	// ConfigState.Member's devices are.
	MemberDevices(memberId Id) []*AclSidecar
	// §8.5's consented(d, M): AclState.ConsentedFor, the one predicate.
	Consented(sidecarId Id, memberId Id) bool
	// The member's recovery binding in effect: ConfigState.CurrentBinding. Nil for none.
	CurrentBinding(memberId Id) *bridge.RecoveryBindingRow
	// Whether §7.9's presence row covers the statement as signed by its signer, so its act needs one presence check
	// by a live key of the signer's: ConfigState.PresenceRequired, from the log, never from a caller.
	PresenceRequired(statement *SidecarStatement) bool
	// The presence keys the sidecar registered that are live at the newest state: ConfigState.LiveKeys.
	LiveKeys(sidecarId Id) []*bridge.KeyRow
	// What a compromise revocation of targetId from sinceN parks and voids, and what stands: ConfigState's cascade
	// closure and CascadePlan, as DeviceRevokePlan's items.
	Cascade(targetId Id, sinceN uint64) ([]DeviceRevokeItem, error)
	// The first entry timed at or after lostAt, and its time, from the retained entries; false when none is.
	ProposedSince(lostAt time.Time) (n uint64, at time.Time, ok bool)
	// Calls callback with each entry applied from now on; the answer removes it.
	AddEntryCallback(callback SidecarAuthorityEntryFunction) func()
}

// The Sidecar's installed authority, under its own lock.
type sidecarAuthorities struct {
	stateLock sync.Mutex
	authority SidecarAuthority
	// raised at each install and removal, for a watcher that follows the newest
	changes uint64
}

// Installs authority as the network's verified state, which every admission gate asks, replacing any before; the
// answer removes it, if it is still the installed one. TEAM-M2-10's ConfigClient installs its adapter once it follows
// the log; a test installs sidecartest.FakeAuthority.
func (self *Sidecar) InstallAuthority(authority SidecarAuthority) func() {
	func() {
		self.authorities.stateLock.Lock()
		defer self.authorities.stateLock.Unlock()
		self.authorities.authority = authority
		self.authorities.changes += 1
	}()
	self.authorityInstalled(authority)
	var once sync.Once
	return func() {
		once.Do(func() {
			removed := func() bool {
				self.authorities.stateLock.Lock()
				defer self.authorities.stateLock.Unlock()
				if self.authorities.authority != authority {
					return false
				}
				self.authorities.authority = nil
				self.authorities.changes += 1
				return true
			}()
			if removed {
				self.authorityInstalled(nil)
			}
		})
	}
}

// The installed authority, nil for none.
func (self *Sidecar) authority() SidecarAuthority {
	self.authorities.stateLock.Lock()
	defer self.authorities.stateLock.Unlock()
	return self.authorities.authority
}
