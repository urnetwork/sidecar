// §9.4's K_sock in the config repo (D-SOCK-13, X3): the file socket/key that a config writer creates with
// the repo and only config writers' heads change (§8.8), the ring a reader builds from a verified head,
// and the rule that says when a writer must rotate it. Every admitted sidecar reads the file through the
// config repo like any config file, agents and overflow member devices by wrap (§7.9), so nothing here
// fetches or unwraps: a ring is made from bytes a verified head already gave.
//
// The overlap follows plan-SOCK-ksock-rotation's answer. While the file holds a previous key, compiles
// emit a target under each key, so gates' MayListen and MayDial refuse neither path, and listers open
// seals under either. Listeners register both paths until rotated_at_ms + Overlap by their own clock,
// so the overlap ends on time even when no writer is online, and the first writer head at or after it
// clears the previous key. What a compile reads is the file alone, never a clock: readers recompile the
// rows a writer's base names and must get the same bytes (§8.8).
//
// On every leg, the sidecar_http page Worker's included, since readers recompile rows there too: root
// Id, no connect type.

package sidecar

import (
	cryptorand "crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Where K_sock lives in the config repo, a single-record file beside policy.hujson
// (plan-SOCK-ksock-rotation #2).
const SocketKeyFilePath = "socket/key"

// A K_sock file a head holds that no rule allows: a key of the wrong size, a previous key without its
// rotation time or the reverse, or a previous key equal to the current. A reader refuses the head's
// socket names, the closed direction.
var ErrSocketKeyFileInvalid = errors.New("invalid socket key file")

// The ring's and the rotation rule's tunables (§9.4).
type SocketKeyRingSettings struct {
	// How long a rotation's two keys both stand: listeners register both paths this long by their own
	// clock, and the first writer head at or after rotated_at_ms plus this clears the previous key. 10
	// min, §9.4's overlap.
	Overlap time.Duration
	// How long other key-holder shrinks and authorization expiries wait before they make a rotation
	// due, counted from the first of them: 24 h, §9.4's at most daily, as §11.6's batched due_by_ms.
	BatchDelay time.Duration
	// How long a due rotation may wait for a writer before member devices alarm: 24 h (§9.4).
	AlarmDelay time.Duration
}

// §9.4's values.
func DefaultSocketKeyRingSettings() *SocketKeyRingSettings {
	return &SocketKeyRingSettings{
		Overlap:    10 * time.Minute,
		BatchDelay: 24 * time.Hour,
		AlarmDelay: 24 * time.Hour,
	}
}

// A new key, from crypto/rand.
func newSocketKey() []byte {
	socketKey := make([]byte, socketKeyByteCount)
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	cryptorand.Read(socketKey)
	testHookSecret("K_sock", socketKey)
	return socketKey
}

// The file a config writer creates with the repo: one fresh key and no rotation (§9.4).
func NewSocketKeyFile() *protocol.SocketKeyFile {
	return &protocol.SocketKeyFile{CurrentKey: newSocketKey()}
}

// The file after a rotation in the head a writer saves at rotatedAtMs: a fresh key, and the current one
// kept as previous. A writer passes the later of its clock and the newest trigger it rotates for, so
// SocketKeyRotationDue counts that trigger covered whatever the skew between its clock and api's. A
// rotation inside another's overlap drops the older previous key, which an immediate trigger warrants.
func RotateSocketKeyFile(file *protocol.SocketKeyFile, rotatedAtMs int64) (*protocol.SocketKeyFile, error) {
	if err := CheckSocketKeyFile(file); err != nil {
		return nil, err
	}
	if rotatedAtMs <= 0 {
		return nil, fmt.Errorf("%w: a rotation at %d", ErrSocketKeyFileInvalid, rotatedAtMs)
	}
	return &protocol.SocketKeyFile{
		CurrentKey:  newSocketKey(),
		PreviousKey: append([]byte(nil), file.GetCurrentKey()...),
		RotatedAtMs: rotatedAtMs,
	}, nil
}

// The file a writer's head saved at headTimeMs holds: the previous key cleared once headTimeMs is at or
// after rotated_at_ms + Overlap, and the file unchanged otherwise. changed says whether the head must
// write the file. Only a writer's head calls this; a reader never applies a clock to the file.
func SettleSocketKeyFile(file *protocol.SocketKeyFile, headTimeMs int64, settings *SocketKeyRingSettings) (*protocol.SocketKeyFile, bool, error) {
	if err := CheckSocketKeyFile(file); err != nil {
		return nil, false, err
	}
	if len(file.GetPreviousKey()) == 0 || headTimeMs < file.GetRotatedAtMs()+settings.Overlap.Milliseconds() {
		return file, false, nil
	}
	return &protocol.SocketKeyFile{CurrentKey: append([]byte(nil), file.GetCurrentKey()...)}, true, nil
}

// Holds the file to its rules. A file is checked whole before any key in it is used.
func CheckSocketKeyFile(file *protocol.SocketKeyFile) error {
	if file == nil {
		return fmt.Errorf("%w: no file", ErrSocketKeyFileInvalid)
	}
	if len(file.GetCurrentKey()) != socketKeyByteCount {
		return fmt.Errorf("%w: a current key of %d bytes", ErrSocketKeyFileInvalid, len(file.GetCurrentKey()))
	}
	switch previousKey := file.GetPreviousKey(); {
	case len(previousKey) == 0:
		if file.GetRotatedAtMs() != 0 {
			return fmt.Errorf("%w: a rotation time with no previous key", ErrSocketKeyFileInvalid)
		}
	case len(previousKey) != socketKeyByteCount:
		return fmt.Errorf("%w: a previous key of %d bytes", ErrSocketKeyFileInvalid, len(previousKey))
	case file.GetRotatedAtMs() <= 0:
		return fmt.Errorf("%w: a previous key with no rotation time", ErrSocketKeyFileInvalid)
	case subtle.ConstantTimeCompare(previousKey, file.GetCurrentKey()) == 1:
		return fmt.Errorf("%w: a previous key equal to the current", ErrSocketKeyFileInvalid)
	}
	return nil
}

// The file a head holds at SocketKeyFilePath, checked.
func ParseSocketKeyFile(fileBytes []byte) (*protocol.SocketKeyFile, error) {
	file := &protocol.SocketKeyFile{}
	if err := proto.Unmarshal(fileBytes, file); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSocketKeyFileInvalid, err)
	}
	if err := CheckSocketKeyFile(file); err != nil {
		return nil, err
	}
	return file, nil
}

// The bytes a writer's head stores, deterministically encoded, so two writers saving one file write the
// same bytes.
func MarshalSocketKeyFile(file *protocol.SocketKeyFile) ([]byte, error) {
	if err := CheckSocketKeyFile(file); err != nil {
		return nil, err
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(file)
}

// One network's keys as a verified head's file holds them: the current, and the previous while the file
// keeps it. Immutable, so safe for concurrent use.
type SocketKeyRing struct {
	current  *SocketKeys
	previous *SocketKeys
	// with previous, the rotating head's time
	rotatedAtMs int64
	settings    *SocketKeyRingSettings
}

// The ring a reader builds from the file in a verified config head of networkId's config repo.
func NewSocketKeyRing(networkId Id, file *protocol.SocketKeyFile, settings *SocketKeyRingSettings) (*SocketKeyRing, error) {
	if err := CheckSocketKeyFile(file); err != nil {
		return nil, err
	}
	current, err := NewSocketKeys(networkId, file.GetCurrentKey())
	if err != nil {
		return nil, err
	}
	ring := &SocketKeyRing{current: current, settings: settings}
	if len(file.GetPreviousKey()) != 0 {
		if ring.previous, err = NewSocketKeys(networkId, file.GetPreviousKey()); err != nil {
			return nil, err
		}
		ring.rotatedAtMs = file.GetRotatedAtMs()
	}
	return ring, nil
}

// The newest keys.
func (self *SocketKeyRing) Current() *SocketKeys {
	return self.current
}

// The previous keys while the file holds them, else nil.
func (self *SocketKeyRing) Previous() *SocketKeys {
	return self.previous
}

// §8's CompileAcl input: the keys every socket target compiles under, newest first, and the previous
// while the file holds it, so rows carry a target under each (plan-SOCK-ksock-rotation). A function of
// the file alone, never of a clock, so every reader's recompile equals the writer's rows.
func (self *SocketKeyRing) CompileKeys() []*SocketKeys {
	if self.previous == nil {
		return []*SocketKeys{self.current}
	}
	return []*SocketKeys{self.current, self.previous}
}

// name's token path under each of CompileKeys, in their order: what a compile emits for one socket.
func (self *SocketKeyRing) CompileTokenPaths(name string) ([][]byte, error) {
	tokenPaths := [][]byte{}
	for _, keys := range self.CompileKeys() {
		tokenPath, err := keys.TokenPath(name)
		if err != nil {
			return nil, err
		}
		tokenPaths = append(tokenPaths, tokenPath)
	}
	return tokenPaths, nil
}

// prefix's whole-segment token prefix under each of CompileKeys, for §8's socket_prefix.
func (self *SocketKeyRing) CompileTokenPrefixes(prefix string) ([][]byte, error) {
	tokenPrefixes := [][]byte{}
	for _, keys := range self.CompileKeys() {
		tokenPrefix, err := keys.TokenPrefix(prefix)
		if err != nil {
			return nil, err
		}
		tokenPrefixes = append(tokenPrefixes, tokenPrefix)
	}
	return tokenPrefixes, nil
}

// The keys a listener registers under at nowMs by its own clock: both until rotated_at_ms + Overlap,
// then the newest alone, whether or not a writer has cleared the file yet (§9.4's 10 min).
func (self *SocketKeyRing) RegisterKeys(nowMs int64) []*SocketKeys {
	if self.previous == nil || self.rotatedAtMs+self.settings.Overlap.Milliseconds() <= nowMs {
		return []*SocketKeys{self.current}
	}
	return []*SocketKeys{self.current, self.previous}
}

// The time, in milliseconds on the listener's clock, from which RegisterKeys gives the newest keys alone, and false
// while the file holds no previous key: a registrar wakes then to drop the previous path (§9.4's 10 min).
func (self *SocketKeyRing) RegisterBothUntilMs() (int64, bool) {
	if self.previous == nil {
		return 0, false
	}
	return self.rotatedAtMs + self.settings.Overlap.Milliseconds(), true
}

// name's token path under each of RegisterKeys at nowMs, newest first: the paths a listener registers.
func (self *SocketKeyRing) RegisterTokenPaths(name string, nowMs int64) ([][]byte, error) {
	tokenPaths := [][]byte{}
	for _, keys := range self.RegisterKeys(nowMs) {
		tokenPath, err := keys.TokenPath(name)
		if err != nil {
			return nil, err
		}
		tokenPaths = append(tokenPaths, tokenPath)
	}
	return tokenPaths, nil
}

// A lister's open (§9.4): the newest keys, then the previous while the file holds them.
func (self *SocketKeyRing) OpenName(nameToken []byte, sealedName []byte) (string, bool) {
	return OpenSocketName(self.current, self.previous, nameToken, sealedName)
}

// What an authorization-log entry, or an expiry at its time, does to the config repo's key holders, in
// §10.5's table, which §9.4 rotates K_sock on.
type SocketKeyEvent int

const (
	// A MemberRevoke: rotate at once.
	SocketKeyEventMemberRemoved SocketKeyEvent = iota + 1
	// A member device's removal, a leaf leaving: rotate at once.
	SocketKeyEventMemberDeviceRemoved
	// A compromise retirement, agents included: a SidecarRevoke or RecoveryRebind for compromise, or a
	// leaked bundle's DelegationRevoke with since_n > 0. Rotate at once.
	SocketKeyEventCompromise
	// Any other key-holder shrink: a reap, revocation or Suspend of an uncovered agent, a
	// DelegationRevoke with since_n 0, or a lost or removed revocation or Suspend of a sidecar a
	// Delegation admitted. Batched.
	SocketKeyEventHolderShrink
	// An authorization expiry: an uncovered agent's SidecarAdmit or a Delegation reaching not_after.
	// Batched.
	SocketKeyEventAuthorizationExpiry
	// A reap of an agent its live Delegation covers, or a covered ephemeral agent's not_after: no
	// holder leaves, so nothing rotates (§10.5).
	SocketKeyEventCoveredAgentReap
)

// How soon an event makes a rotation due.
type SocketKeyTriggerClass int

const (
	// Never: no holder left.
	SocketKeyTriggerNone SocketKeyTriggerClass = iota
	// At the event's own time.
	SocketKeyTriggerImmediate
	// BatchDelay after the first such event.
	SocketKeyTriggerBatched
)

// §9.4's classes. An event this code does not know rotates at once, the closed direction.
func (self SocketKeyEvent) Class() SocketKeyTriggerClass {
	switch self {
	case SocketKeyEventHolderShrink, SocketKeyEventAuthorizationExpiry:
		return SocketKeyTriggerBatched
	case SocketKeyEventCoveredAgentReap:
		return SocketKeyTriggerNone
	}
	return SocketKeyTriggerImmediate
}

// One event since the last rotation, at its entry's time_ms or, for an expiry, at its T_e.
type SocketKeyTrigger struct {
	Event  SocketKeyEvent
	TimeMs int64
}

// When K_sock must rotate and when member devices alarm that it has not.
type SocketKeyRotationVerdict struct {
	// The next writer head rotates.
	Due bool
	// When the rotation fell or falls due, 0 when nothing is pending.
	DueAtMs int64
	// Member devices raise their alarm: no writer has rotated for AlarmDelay past DueAtMs.
	Alarm bool
	// When they do, 0 when nothing is pending.
	AlarmAtMs int64
}

// The triggers of triggers that a rotation saved at rotatedAtMs has not covered: those after it. A
// file holding no rotation time has covered nothing since the key was made, and the caller passes the
// time the key was created, or 0 for none.
func PendingSocketKeyTriggers(triggers []*SocketKeyTrigger, rotatedAtMs int64) []*SocketKeyTrigger {
	pending := []*SocketKeyTrigger{}
	for _, trigger := range triggers {
		if rotatedAtMs < trigger.TimeMs {
			pending = append(pending, trigger)
		}
	}
	return pending
}

// §9.4's rotation rule over the triggers no rotation has covered yet, at nowMs. A member's or member
// device's removal and a compromise retirement are due at once; other shrinks and expiries BatchDelay
// after the first, so they rotate at most daily; a covered agent's reap never. Members alarm AlarmDelay
// after a rotation fell due, which for an immediate trigger is AlarmDelay after the trigger itself.
// A function of its arguments, so a writer and every member device reach one verdict.
func SocketKeyRotationDue(pending []*SocketKeyTrigger, nowMs int64, settings *SocketKeyRingSettings) *SocketKeyRotationVerdict {
	due := false
	dueAtMs := int64(0)
	batched := false
	firstBatchedMs := int64(0)
	for _, trigger := range pending {
		switch trigger.Event.Class() {
		case SocketKeyTriggerImmediate:
			if !due || trigger.TimeMs < dueAtMs {
				due = true
				dueAtMs = trigger.TimeMs
			}
		case SocketKeyTriggerBatched:
			if !batched || trigger.TimeMs < firstBatchedMs {
				batched = true
				firstBatchedMs = trigger.TimeMs
			}
		}
	}
	if batched {
		if batchedDueMs := firstBatchedMs + settings.BatchDelay.Milliseconds(); !due || batchedDueMs < dueAtMs {
			due = true
			dueAtMs = batchedDueMs
		}
	}
	verdict := &SocketKeyRotationVerdict{}
	if !due {
		return verdict
	}
	verdict.DueAtMs = dueAtMs
	verdict.Due = dueAtMs <= nowMs
	verdict.AlarmAtMs = dueAtMs + settings.AlarmDelay.Milliseconds()
	verdict.Alarm = verdict.AlarmAtMs <= nowMs
	return verdict
}
