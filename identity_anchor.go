// SidecarAnchor (CORE-M2-01, §5.6's genesis row, §7.9): the network an enrollment's credential vouches for, A_0 =
// SHA-256(Signed Genesis), and the head its creator stood at. An invite or a pre-approved key brings one, and the
// sidecar records it in the core's namespace of its keychain at enrollment, before anything reads the log, so the
// ConfigClient that follows the log (TEAM-M2-10) checks every genesis and pin it is shown against it: another genesis
// is refused, and so is a pin below the anchored head (I-16). A `ur login` device has no such credential, so it trusts
// the first genesis it is shown (TrustFirstUse) and shows its SafetyNumber for its admitter to compare: the record
// says which.
//
// The record is one fixed layout, so a change of it is a new version: version (1) | source (1) | genesis_sha256 (32)
// | head version (8, big endian; 0 for none) | head chain (32, zero for none).
//
// On every leg: root Id, no connect type.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The keychain record of the core's namespace holding the anchor.
const sidecarAnchorRecordName = "anchor"

// The record's format values.
const (
	sidecarAnchorRecordVersion   = 1
	sidecarAnchorRecordByteCount = 1 + 1 + sha256.Size + 8 + sha256.Size
)

// How a sidecar learned its anchor.
type SidecarAnchorSource uint8

const (
	// An invite's anchor (§7.5): its genesis hash and head.
	SidecarAnchorInvite SidecarAnchorSource = 1
	// A pre-approved auth key's bundle (§7.8).
	SidecarAnchorAuthKey SidecarAnchorSource = 2
	// The first genesis a `ur login` device was shown, trusted on first use: its admitter compares the safety number.
	SidecarAnchorFirstUse SidecarAnchorSource = 3
)

var (
	// The log is another network's than the anchored one, or below the anchored head: refused (§5.6's genesis row,
	// S1's "a genesis other than the invite's refused").
	ErrSidecarAnchorMismatch = errors.New("the log does not chain to the anchored genesis and head")
	// An anchor that is not 32 bytes of genesis hash and, when a head is given, a 32-byte chain.
	ErrSidecarAnchorMalformed = errors.New("the anchor is not a genesis hash and a head")
)

// The genesis and head a sidecar's log must chain to.
type SidecarAnchor struct {
	// A_0 = SHA-256(Signed Genesis).
	GenesisSha256 []byte
	// The log position the anchor's creator stood at. Nil: none, as on first use.
	Head   *bridge.AuthPin
	Source SidecarAnchorSource
}

// Checks a log against the anchor: genesisSha256 must be the anchored A_0, and pin, the newest the log is at, must not
// be below the anchored head. A pin at the head's version must carry its chain. ErrSidecarAnchorMismatch otherwise.
func (self *SidecarAnchor) Check(genesisSha256 []byte, pin *bridge.AuthPin) error {
	if !bytes.Equal(self.GenesisSha256, genesisSha256) {
		return fmt.Errorf("%w: another genesis", ErrSidecarAnchorMismatch)
	}
	if self.Head == nil {
		return nil
	}
	if pin == nil || pin.GetVersion() < self.Head.GetVersion() {
		return fmt.Errorf("%w: below the anchored head", ErrSidecarAnchorMismatch)
	}
	if pin.GetVersion() == self.Head.GetVersion() && !bytes.Equal(pin.GetChain(), self.Head.GetChain()) {
		return fmt.Errorf("%w: another chain at the anchored head", ErrSidecarAnchorMismatch)
	}
	return nil
}

// The record's bytes.
func (self *SidecarAnchor) encode() ([]byte, error) {
	if len(self.GenesisSha256) != sha256.Size || (self.Head != nil && (self.Head.GetVersion() == 0 || len(self.Head.GetChain()) != sha256.Size)) {
		return nil, ErrSidecarAnchorMalformed
	}
	switch self.Source {
	case SidecarAnchorInvite, SidecarAnchorAuthKey, SidecarAnchorFirstUse:
	default:
		return nil, ErrSidecarAnchorMalformed
	}
	record := make([]byte, 0, sidecarAnchorRecordByteCount)
	record = append(record, sidecarAnchorRecordVersion, byte(self.Source))
	record = append(record, self.GenesisSha256...)
	chain := make([]byte, sha256.Size)
	version := uint64(0)
	if self.Head != nil {
		version = self.Head.GetVersion()
		copy(chain, self.Head.GetChain())
	}
	record = binary.BigEndian.AppendUint64(record, version)
	return append(record, chain...), nil
}

// The anchor a record holds, ErrSidecarStoreFailed for one that is not one.
func decodeSidecarAnchor(record []byte) (*SidecarAnchor, error) {
	if len(record) != sidecarAnchorRecordByteCount || record[0] != sidecarAnchorRecordVersion {
		return nil, fmt.Errorf("%w: an anchor record", ErrSidecarStoreFailed)
	}
	anchor := &SidecarAnchor{Source: SidecarAnchorSource(record[1]), GenesisSha256: bytes.Clone(record[2 : 2+sha256.Size])}
	switch anchor.Source {
	case SidecarAnchorInvite, SidecarAnchorAuthKey, SidecarAnchorFirstUse:
	default:
		return nil, fmt.Errorf("%w: an anchor record", ErrSidecarStoreFailed)
	}
	headStart := 2 + sha256.Size
	if version := binary.BigEndian.Uint64(record[headStart:]); version != 0 {
		anchor.Head = &bridge.AuthPin{Version: version, Chain: bytes.Clone(record[headStart+8:])}
	}
	return anchor, nil
}

// Keeps anchor in the core's namespace, replacing nothing: an anchor once recorded is the sidecar's for its life, and a
// second one, even equal, is refused unless it is the same bytes.
func persistSidecarAnchor(secrets SidecarSecrets, anchor *SidecarAnchor) error {
	record, err := anchor.encode()
	if err != nil {
		return err
	}
	existing, err := secrets.Get(sidecarAnchorRecordName)
	switch {
	case err == nil:
		if bytes.Equal(existing, record) {
			return nil
		}
		return fmt.Errorf("%w: another anchor is recorded", ErrSidecarAnchorMismatch)
	case !errors.Is(err, ErrSidecarStoreAbsent):
		return err
	}
	return secrets.Put(sidecarAnchorRecordName, record)
}

// The anchor of a credential, nil when it brings none: an invite's, or a pre-approved key's bundle's.
func sidecarAnchorOfCredential(credential *SidecarEnrollCredential, bundle *AuthKeyBundle) (*SidecarAnchor, error) {
	switch {
	case credential.Anchor != nil:
		anchor := &SidecarAnchor{GenesisSha256: bytes.Clone(credential.Anchor.GenesisSha256), Source: SidecarAnchorInvite}
		if credential.Anchor.HeadVersion != 0 {
			anchor.Head = &bridge.AuthPin{Version: credential.Anchor.HeadVersion, Chain: bytes.Clone(credential.Anchor.HeadChain)}
		}
		if _, err := anchor.encode(); err != nil {
			return nil, err
		}
		return anchor, nil
	case bundle != nil:
		anchor := &SidecarAnchor{
			GenesisSha256: bytes.Clone(bundle.GenesisSha256),
			Head:          &bridge.AuthPin{Version: bundle.HeadVersion, Chain: bytes.Clone(bundle.HeadChain)},
			Source:        SidecarAnchorAuthKey,
		}
		if _, err := anchor.encode(); err != nil {
			return nil, err
		}
		return anchor, nil
	}
	return nil, nil
}

// The anchor this sidecar recorded: what TEAM-M2-10's ConfigClient checks every genesis and pin against before it
// trusts any of the log. ErrSidecarStoreAbsent when none is recorded, which a ConfigClient answers with
// TrustFirstUse on a `ur login` device and by refusing everywhere else.
func (self *Sidecar) Anchor() (*SidecarAnchor, error) {
	secrets := self.currentCoreSecrets()
	if secrets == nil {
		return nil, ErrSidecarNoIdentity
	}
	record, err := secrets.Get(sidecarAnchorRecordName)
	if err != nil {
		return nil, err
	}
	return decodeSidecarAnchor(record)
}

// Records genesisSha256 as this sidecar's anchor on first use, for a device whose enrollment brought none (§5.6's
// genesis row): its admitter then compares SafetyNumber. A recorded anchor is never replaced: one already recorded
// answers its own Check of genesisSha256, so another network's genesis is refused here too.
func (self *Sidecar) TrustFirstUse(genesisSha256 []byte) error {
	existing, err := self.Anchor()
	switch {
	case err == nil:
		return existing.Check(genesisSha256, existing.Head)
	case !errors.Is(err, ErrSidecarStoreAbsent):
		return err
	}
	secrets := self.currentCoreSecrets()
	if secrets == nil {
		return ErrSidecarNoIdentity
	}
	return persistSidecarAnchor(secrets, &SidecarAnchor{GenesisSha256: bytes.Clone(genesisSha256), Source: SidecarAnchorFirstUse})
}

// The core's namespace of this network's keychain, nil before the sidecar knows its network: the one the run loop
// adopted, else, between an enrollment and the run loop's next look, the enrolled network's.
func (self *Sidecar) currentCoreSecrets() SidecarSecrets {
	var networkId *Id
	secrets := func() SidecarSecrets {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.networkId != nil {
			id := *self.networkId
			networkId = &id
		}
		return self.coreSecrets
	}()
	if secrets == nil && networkId != nil && self.instance != nil {
		secrets = self.instance.secrets(*networkId, sidecarCoreSecretsNamespace)
	}
	return secrets
}
