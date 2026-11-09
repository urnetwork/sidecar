//go:build !sidecar_http

// Hello's admission check (§6.4's second half; D-PROTO-13, I-3, R-PROTO-12): from M2 the key a peer's
// binding must name is the identity key of its SidecarAdmit in this sidecar's verified config state
// (§7.9), which is chained to the genesis its invite or auth key carried, or was trusted on first use
// with a safety number (§2.8 EX5, whose comparison is §5.6's and §7.9's). A binding is no longer pinned
// by its own first use, so §2.8's EX6 ends here, and identityPinSource reads the state instead
// (admissionIdentityPins). A Subprotocol runs on this source whenever its env carries Admissions.
//
// What a Hello or HelloResult must show, beyond rpc_identity.go's checks 1 to 5:
//
//   - an admission this side's state holds for the binding's sidecar_id, neither revoked nor parked by
//     §7.9's cascade, and for an agent before its not_after, as Sidecar.Admitted reads this sidecar's
//     own; else UNAUTHENTICATED;
//   - a sidecar_id the state does not name first gets one catch-up of the config, with no alarm, since
//     its admission may have landed after this side last followed the log; still unknown after it,
//     UNAUTHENTICATED;
//   - the admission's identity key, else UNAUTHENTICATED and key_changed;
//   - a generation no lower than the highest this side has seen for the sidecar_id, which persists as
//     M1's pins did, so a replayed older binding cannot stand in for a newer one.
//
// A sidecar that is not itself admitted, or holds no verified state, gets no peer (§5.6): it sends no
// Hello and answers every Hello UNAVAILABLE, the side at fault being its own. Agents and read_only
// devices are peers like any other. A suspended peer passes: suspension gates grants and witnessing,
// not identity (§6.4's witness row), and an admission row carries none.
//
// M1's first-use pins: the first time this source runs with a state installed, it reads each one, and
// one that names another key than its sidecar_id's admission raises key_changed, the admission
// winning. Each is then dropped, its generation carried into this source's own floors.
//
// The state is read only through SidecarAuthority (CORE-M2-01, C-10), so this runs on
// sidecartest.FakeAuthority until TEAM-M2-10's adapter installs the real one. A catch-up is the
// authority's to offer (SidecarAuthorityCatchUp); one that does not offer it is not caught up, and an
// unknown peer is refused at once.
//
// A Hello stands until HelloCacheTimeout, while its peer's admission does: once the state moves past the
// position the admission was read at, the next frame or call from or to that peer reads it again, and a
// revocation or park closes the gate then (peerAdmissionStands).

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
)

var (
	// No admission names the peer's sidecar_id at this side's state, after one catch-up.
	errHelloUnadmitted = errors.New("hello: no admission names the peer")
	// The peer's admission is revoked.
	errHelloRevoked = errors.New("hello: the peer's admission is revoked")
	// §7.9's cascade parks the peer's admission.
	errHelloParked = errors.New("hello: the peer's admission is parked")
	// This side holds no verified state, or its state does not admit it, so it takes no peer (§5.6).
	errHelloNotAdmitted = errors.New("hello: this sidecar is not admitted")
)

// What Hello's admission check reads of the sidecar that runs the Subprotocol. The Sidecar implements
// it (sidecarSubprotocolAdmissions); a test passes one over sidecartest.FakeAuthority. Safe for
// concurrent use.
type SubprotocolAdmissions interface {
	// The network's verified state as InstallAuthority holds it now; nil while none is installed.
	Authority() SidecarAuthority
	// Whether this sidecar is admitted (Sidecar.Admitted): one that is not takes no peer.
	Admitted() bool
}

// An authority that can follow the log on demand. TEAM-M2-10's adapter implements it over its
// ConfigClient's follow, and a Hello from a peer the state does not name asks it once. An authority
// without it is not caught up.
type SidecarAuthorityCatchUp interface {
	// Applies what api serves now, answering once that is applied or ctx ends. The state that moved is
	// read again through SidecarAuthority, never through this.
	CatchUp(ctx context.Context) error
}

// A deep copy, nil for nil.
func cloneAclSidecar(admission *AclSidecar) *AclSidecar {
	if admission == nil {
		return nil
	}
	clone := *admission
	clone.TagIds = slices.Clone(admission.TagIds)
	if admission.Row != nil {
		clone.Row = proto.CloneOf(admission.Row)
	}
	return &clone
}

// Why an admission does not stand for sidecarId at timeMs: nil when it does. An admission whose row
// names another sidecar is no admission of this one.
func admissionStanding(admission *AclSidecar, sidecarId Id, timeMs int64) error {
	switch {
	case admission == nil || admission.Row == nil || !bytes.Equal(admission.Row.GetSidecarId(), sidecarId.Bytes()):
		return errHelloUnadmitted
	case admission.Row.GetRevokedAt() != 0:
		return errHelloRevoked
	case admission.Row.GetParkedAt() != 0:
		return errHelloParked
	}
	// an admission's not_after binds agents only (§7.9); an expired one admits nothing
	if notAfter := admission.Row.GetNotAfter(); notAfter != 0 && notAfter <= timeMs {
		return errHelloUnadmitted
	}
	return nil
}

// The generation floor file's form: a magic and version byte, then the generation, big endian.
const (
	admissionGenerationMagic     = "URGEN"
	admissionGenerationVersion   = 1
	admissionGenerationByteCount = len(admissionGenerationMagic) + 1 + 8
)

// The file a sidecar_id's generation floor is kept in.
func admissionGenerationName(sidecarId Id) string {
	return "generations/" + sidecarId.String()
}

// The floor a file holds, or ErrSidecarStoreFailed for bytes of any other form.
func decodeAdmissionGeneration(encoded []byte) (int64, error) {
	if len(encoded) != admissionGenerationByteCount || string(encoded[:len(admissionGenerationMagic)]) != admissionGenerationMagic ||
		encoded[len(admissionGenerationMagic)] != admissionGenerationVersion {
		return 0, fmt.Errorf("%w: a generation file of another form", ErrSidecarStoreFailed)
	}
	generation := int64(binary.BigEndian.Uint64(encoded[len(admissionGenerationMagic)+1:]))
	if generation < 1 {
		return 0, fmt.Errorf("%w: a generation below 1", ErrSidecarStoreFailed)
	}
	return generation, nil
}

// A floor's file bytes.
func encodeAdmissionGeneration(generation int64) []byte {
	encoded := make([]byte, 0, admissionGenerationByteCount)
	encoded = append(encoded, admissionGenerationMagic...)
	encoded = append(encoded, admissionGenerationVersion)
	return binary.BigEndian.AppendUint64(encoded, uint64(generation))
}

// One catch-up in flight, which every check that finds a peer unknown meanwhile joins.
type admissionCatchUp struct {
	done chan struct{}
	err  error
}

// M2's identityPinSource: the peer's SidecarAdmit in this side's verified state, with a durable
// generation floor per sidecar_id in the Subprotocol's sealed store, one file a sidecar_id under
// generations/. See the file header.
type admissionIdentityPins struct {
	// the Subprotocol's, which ends a catch-up still running when it closes
	ctx        context.Context
	admissions SubprotocolAdmissions
	store      SidecarStore
	settings   *SidecarProtocolSettings
	clock      Clock
	// where a first-use pin that the admission contradicts raises key_changed
	raiseEvent func(event SidecarEvent)

	// Serializes each check's floor read and write, as firstUseIdentityPins' lock does, and the one pass
	// over M1's pins. Held across the store's I/O, never across a catch-up.
	pinLock sync.Mutex
	// the floors the store holds, read once per sidecar_id and written with it
	sidecarIdGenerations map[Id]int64
	// M1's first-use pins have been read and dropped
	firstUseDropped bool

	catchUpLock sync.Mutex
	catchUp     *admissionCatchUp
}

// The admission source for a Subprotocol: its ctx, admissions and store, and where key_changed goes.
func newAdmissionIdentityPins(
	ctx context.Context,
	admissions SubprotocolAdmissions,
	store SidecarStore,
	settings *SidecarProtocolSettings,
	clock Clock,
	raiseEvent func(event SidecarEvent),
) *admissionIdentityPins {
	return &admissionIdentityPins{
		ctx:                  ctx,
		admissions:           admissions,
		store:                store,
		settings:             settings,
		clock:                clock,
		raiseEvent:           raiseEvent,
		sidecarIdGenerations: map[Id]int64{},
	}
}

// See identityPinSource and the file header: the admission must stand and name the binding's key, and
// the generation reach the floor, which a higher one raises before this answers.
func (self *admissionIdentityPins) checkPin(ctx context.Context, sidecarId Id, identityPublicKey []byte, generation int64) (*identityPinAdmission, error) {
	if len(identityPublicKey) != ed25519.PublicKeySize || generation < 1 {
		return nil, errHelloPinMismatch
	}
	authority := self.admissions.Authority()
	if authority == nil || !self.admissions.Admitted() {
		return nil, errHelloNotAdmitted
	}
	// the position first, so the admission read after it is at least as new
	stateVersion := authority.Pin().GetVersion()
	admission := authority.Admission(sidecarId)
	if admission == nil {
		// one catch-up, with no alarm: an admission that landed after this side last followed the log
		if err := self.catchUpOnce(ctx, authority); err != nil {
			return nil, err
		}
		if authority = self.admissions.Authority(); authority == nil {
			return nil, errHelloNotAdmitted
		}
		stateVersion = authority.Pin().GetVersion()
		admission = authority.Admission(sidecarId)
	}
	if err := admissionStanding(admission, sidecarId, self.clock.Now().UnixMilli()); err != nil {
		return nil, err
	}

	self.pinLock.Lock()
	defer self.pinLock.Unlock()
	if err := self.dropFirstUsePinsWithLock(authority); err != nil {
		return nil, err
	}
	if !bytes.Equal(admission.Row.GetIdentityPublicKey(), identityPublicKey) {
		return nil, errHelloPinMismatch
	}
	floor, err := self.loadGenerationWithLock(sidecarId)
	if err != nil {
		return nil, err
	}
	if generation < floor {
		return nil, errHelloGenerationBelow
	}
	if floor < generation {
		if err := self.storeGenerationWithLock(sidecarId, generation); err != nil {
			return nil, err
		}
	}
	return &identityPinAdmission{admission: cloneAclSidecar(admission), stateVersion: stateVersion}, nil
}

// Runs the authority's catch-up, or joins one in flight, waiting at most DefaultCallTimeout on this
// side's clock and never past ctx. An authority that offers none is not caught up, which is no error:
// the peer stays unknown. A catch-up that fails or does not finish is an error, which refuses the
// Hello UNAVAILABLE rather than as unknown, since the state was never read.
func (self *admissionIdentityPins) catchUpOnce(ctx context.Context, authority SidecarAuthority) error {
	catchUpAuthority, ok := authority.(SidecarAuthorityCatchUp)
	if !ok {
		return nil
	}
	var flight *admissionCatchUp
	owner := false
	func() {
		self.catchUpLock.Lock()
		defer self.catchUpLock.Unlock()
		if self.catchUp == nil {
			self.catchUp = &admissionCatchUp{done: make(chan struct{})}
			owner = true
		}
		flight = self.catchUp
	}()
	if owner {
		go func() {
			catchUpCtx, cancel := context.WithCancel(self.ctx)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				testHookBarrier("rpc.hello_catch_up.before", "")
				result <- catchUpAuthority.CatchUp(catchUpCtx)
			}()
			var err error
			select {
			case err = <-result:
			case <-self.clock.After(self.settings.DefaultCallTimeout):
				cancel()
				err = <-result
				if err == nil {
					err = context.DeadlineExceeded
				}
			}
			testHookBarrier("rpc.hello_catch_up.after", "")
			func() {
				self.catchUpLock.Lock()
				defer self.catchUpLock.Unlock()
				flight.err = err
				self.catchUp = nil
			}()
			close(flight.done)
		}()
	}
	select {
	case <-flight.done:
		if flight.err != nil {
			return fmt.Errorf("hello: catch-up: %w", flight.err)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Reads M1's first-use pins once and drops them: one that names another key than its sidecar_id's
// admission raises key_changed, the admission winning, and each one's generation becomes a floor here.
// Called with pinLock held. A read that fails leaves the pass for the next check, and refuses this one.
func (self *admissionIdentityPins) dropFirstUsePinsWithLock(authority SidecarAuthority) error {
	if self.firstUseDropped {
		return nil
	}
	entries, err := self.store.List("pins/")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := strings.TrimPrefix(entry.Name, "pins/")
		sidecarId, err := ParseId(name)
		if err != nil {
			// nothing M1 wrote: left for whoever did
			continue
		}
		pin, err := func() (*identityPin, error) {
			reader, err := self.store.Open(identityPinName(sidecarId))
			if err != nil {
				return nil, err
			}
			defer reader.Close()
			encoded, err := io.ReadAll(io.LimitReader(reader, int64(identityPinByteCount)+1))
			if err != nil {
				return nil, err
			}
			return decodeIdentityPin(encoded)
		}()
		if err != nil && !errors.Is(err, ErrSidecarStoreAbsent) {
			if !errors.Is(err, ErrSidecarStoreFailed) {
				return err
			}
			// a pin of another form pins nothing: dropped below
			pin = nil
		}
		if pin != nil {
			if admission := authority.Admission(sidecarId); admission != nil && admission.Row != nil &&
				!bytes.Equal(admission.Row.GetIdentityPublicKey(), pin.identityPublicKey[:]) {
				conflictId := sidecarId
				self.raiseEvent(SidecarEvent{Kind: SidecarEventKeyChanged, SidecarId: &conflictId})
			}
			floor, err := self.loadGenerationWithLock(sidecarId)
			if err != nil {
				return err
			}
			if floor < pin.generation {
				if err := self.storeGenerationWithLock(sidecarId, pin.generation); err != nil {
					return err
				}
			}
		}
		if err := self.store.Remove(identityPinName(sidecarId)); err != nil {
			return err
		}
	}
	self.firstUseDropped = true
	return nil
}

// The stored floor, 0 when the store holds none. Called with pinLock held.
func (self *admissionIdentityPins) loadGenerationWithLock(sidecarId Id) (int64, error) {
	if generation, ok := self.sidecarIdGenerations[sidecarId]; ok {
		return generation, nil
	}
	reader, err := self.store.Open(admissionGenerationName(sidecarId))
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer reader.Close()
	encoded, err := io.ReadAll(io.LimitReader(reader, int64(admissionGenerationByteCount)+1))
	if err != nil {
		return 0, err
	}
	generation, err := decodeAdmissionGeneration(encoded)
	if err != nil {
		return 0, err
	}
	self.sidecarIdGenerations[sidecarId] = generation
	return generation, nil
}

// Writes the floor durably, then keeps it. Called with pinLock held.
func (self *admissionIdentityPins) storeGenerationWithLock(sidecarId Id, generation int64) error {
	testHookBarrier("rpc.hello_pin.before", sidecarId.String())
	defer testHookBarrier("rpc.hello_pin.after", sidecarId.String())
	writer, err := self.store.Create(admissionGenerationName(sidecarId))
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(encodeAdmissionGeneration(generation)); err != nil {
		return err
	}
	if err := writer.Commit(); err != nil {
		return err
	}
	self.sidecarIdGenerations[sidecarId] = generation
	return nil
}

// Whether this side may take a peer at all: always under M1's first-use pins; from M2 only while a
// verified state is installed and admits it (§5.6).
func (self *Subprotocol) selfAdmitted() bool {
	if self.admissions == nil {
		return true
	}
	return self.admissions.Authority() != nil && self.admissions.Admitted()
}

// Whether the Hello standing for sourceId still stands at this side's state, closing the gate when it
// does not. A Hello read its peer's admission at one position of the state; once the state has moved
// past it, the admission is read again: revoked, parked, expired or gone, or this side itself no longer
// admitted, and the gate closes, so the next frame is refused UNAUTHENTICATED and the next call runs a
// Hello, which the same check refuses. The state rarely moves, so most frames read one position and
// compare. Under M1's first-use pins, or with no Hello standing, this answers true and changes nothing:
// the gate's own check is the identity gate's.
func (self *Subprotocol) peerAdmissionStands(sourceId connect.Id) bool {
	if self.admissions == nil {
		return true
	}
	var peer *SubprotocolPeerIdentity
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if identity, ok := self.sourceIdIdentities[sourceId]; ok {
			peer = identity.peer
		}
	}()
	if peer == nil {
		return true
	}
	authority := self.admissions.Authority()
	if authority == nil {
		self.forgetPeerIdentity(sourceId, peer)
		return false
	}
	stateVersion := authority.Pin().GetVersion()
	if stateVersion == peer.AdmissionVersion {
		return true
	}
	if !self.admissions.Admitted() || admissionStanding(authority.Admission(peer.SidecarId), peer.SidecarId, self.clock.Now().UnixMilli()) != nil {
		self.forgetPeerIdentity(sourceId, peer)
		return false
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if identity, ok := self.sourceIdIdentities[sourceId]; ok && identity.peer == peer && peer.AdmissionVersion < stateVersion {
			// a copy, since PeerIdentity hands out clones of the record a reader may hold
			moved := peer.clone()
			moved.AdmissionVersion = stateVersion
			identity.peer = moved
			self.sourceIdIdentities[sourceId] = identity
		}
	}()
	return true
}

// Closes the gate for sourceId if it still holds peer's Hello, and not a newer one that verified since.
func (self *Subprotocol) forgetPeerIdentity(sourceId connect.Id, peer *SubprotocolPeerIdentity) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if identity, ok := self.sourceIdIdentities[sourceId]; ok && identity.peer == peer {
		delete(self.sourceIdIdentities, sourceId)
	}
}

// The Sidecar's admissions as Hello reads them.
type sidecarSubprotocolAdmissions struct {
	sidecar *Sidecar
}

// See SubprotocolAdmissions.
func (self sidecarSubprotocolAdmissions) Authority() SidecarAuthority {
	return self.sidecar.authority()
}

// See SubprotocolAdmissions.
func (self sidecarSubprotocolAdmissions) Admitted() bool {
	return self.sidecar.Admitted()
}
