//go:build !ios_extension

// CanonicalAction.sealed_detail (§16.8; owner decision 220; QD-740): what a dial or route grant's clear fields may not
// show a server, its prefixes and ports, as a CanonicalActionDetail sealed in the one format every sealed field of a
// config record takes (config_seal.go; plan-TEAM-sealed-field-format), under the config repo's key generation. The
// stored action carries the ciphertext, which payload_sha256 and action_id cover, so api's match check stays what it
// was and reads ids alone; an approver's device and every reader open the detail before they render or enforce it,
// and a device that cannot open it refuses the action rather than show it short (D-MCP-17).
//
//	cidrs        a route's prefixes
//	target_port  a forward's port on its target, or an access request's on its worker
//	grant_dst    the grant's destinations that name a port or a prefix, in §8.4's grammar: sidecar:<id>:tcp:<port>,
//	             ip:<cidr>; the clear grant_dst names the same sidecars by id alone
//
// A detail is held to its action: a sidecar it names a port of is one the clear grant_dst names, so the ports a
// device enforces are the ports of a destination api folded into the grant's rule, never another's.
//
// The seal is bound to the action's own clear fields (QD-771). An action has no StatementHeader, so the context a
// record's header gives comes from the action itself (CanonicalActionDetailSealContext): SIGNED_GRANT_ACTIVATE, the
// network, and in the nonce's place the first 16 bytes of SHA-256 over the action's bytes as stored with field 38 cut
// out. A daemon seals once the clear fields are final (NewSealedCanonicalAction; Sidecar.SealActionDetail, which
// AclGrantFiler builds a forward's grant through), and an approver's render and every reader open under what the
// stored bytes derive (OpenCanonicalActionDetail; Sidecar.OpenActionDetail, which ApprovalApprover opens through). No
// function here takes a context its caller made, so a detail opens only beside the clear fields it was sealed with,
// in its network.
//
// EvsRepoKey.DeriveKey runs testHookSecret at the statement key. Package-level functions are safe for concurrent use.
// On every leg but the ios_extension legs, whose forwarding role builds and approves nothing.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A CanonicalActionDetail that is not one its action may carry: empty, a port that is none, a prefix or a destination
// that does not read, a destination that names no port or prefix, or a sidecar the clear grant_dst does not name.
var ErrCanonicalActionDetailInvalid = errors.New("canonical action detail invalid")

// Opens an action's sealed_detail on an approver's or a reader's device: the config repo's key of the generation the
// detail names, under what the action's own bytes derive (CanonicalActionDetailSealContext) in the device's network.
// nil with no error for an action that carries none; ErrConfigSealGenerationMissing while the device lacks the
// generation; ErrConfigSealInvalid or ErrCanonicalActionDetailInvalid for one that does not open or is not its
// action's; ErrCanonicalActionInvalid for stored bytes that derive no context. Sidecar is the device's. Safe for
// concurrent use.
type CanonicalActionDetailOpener interface {
	OpenActionDetail(action *StoredCanonicalAction) (*protocol.CanonicalActionDetail, error)
}

// Builds a daemon's action whose sealed_detail it seals: clear, its clear fields final, with detail sealed under the
// config repo's current key, bound to those fields in the device's network (NewSealedCanonicalAction). Sidecar is the
// device's. Safe for concurrent use.
type CanonicalActionDetailSealer interface {
	SealActionDetail(ctx context.Context, clear *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail) (*StoredCanonicalAction, error)
}

var (
	_ CanonicalActionDetailOpener = (*Sidecar)(nil)
	_ CanonicalActionDetailSealer = (*Sidecar)(nil)
)

// The sidecar a clear grant_dst entry names, false for another kind of destination.
func canonicalActionGrantDstSidecar(dst string) (string, bool) {
	kind, value, found := strings.Cut(dst, ":")
	if !found || kind != "sidecar" {
		return "", false
	}
	id, _, _ := strings.Cut(value, ":")
	return id, true
}

// Whether text is a prefix in its one form: an address and a length, the host bits clear.
func canonicalActionPrefixForm(text string) bool {
	prefix, err := netip.ParsePrefix(text)
	return err == nil && prefix == prefix.Masked() && prefix.String() == text
}

// Holds a detail to the action that carries it: it holds something; target_port is a port; each cidr is a prefix in
// its one form; each grant_dst entry is one a clear field may not hold, a sidecar's port as ParseAclGrantDst reads it
// or an ip: prefix; and each sidecar it names a port of is one the action's clear grant_dst names. action nil checks
// the detail alone.
func CheckCanonicalActionDetail(action *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail) error {
	if detail == nil {
		return fmt.Errorf("%w: no detail", ErrCanonicalActionDetailInvalid)
	}
	if len(detail.ProtoReflect().GetUnknown()) != 0 {
		return fmt.Errorf("%w: a field this build cannot name", ErrCanonicalActionDetailInvalid)
	}
	if len(detail.GetCidrs()) == 0 && detail.GetTargetPort() == 0 && len(detail.GetGrantDst()) == 0 {
		return fmt.Errorf("%w: an empty detail", ErrCanonicalActionDetailInvalid)
	}
	if math.MaxUint16 < detail.GetTargetPort() {
		return fmt.Errorf("%w: target_port %d", ErrCanonicalActionDetailInvalid, detail.GetTargetPort())
	}
	// the values stay out of the errors, which a log may carry (I-13)
	for i, cidr := range detail.GetCidrs() {
		if !canonicalActionPrefixForm(cidr) {
			return fmt.Errorf("%w: cidrs[%d] is no prefix", ErrCanonicalActionDetailInvalid, i)
		}
	}
	clearSidecars := []string{}
	for _, dst := range action.GetGrantDst() {
		if id, ok := canonicalActionGrantDstSidecar(dst); ok {
			clearSidecars = append(clearSidecars, id)
		}
	}
	for i, dst := range detail.GetGrantDst() {
		if canonicalActionGrantDstClear(dst) {
			return fmt.Errorf("%w: grant_dst[%d] names no port or prefix", ErrCanonicalActionDetailInvalid, i)
		}
		if prefix, isPrefix := strings.CutPrefix(dst, "ip:"); isPrefix {
			if !canonicalActionPrefixForm(prefix) {
				return fmt.Errorf("%w: grant_dst[%d] is no prefix", ErrCanonicalActionDetailInvalid, i)
			}
			continue
		}
		if _, port, err := ParseAclGrantDst(dst); err != nil || port == nil {
			return fmt.Errorf("%w: grant_dst[%d] is no sidecar's port", ErrCanonicalActionDetailInvalid, i)
		}
		if id, _ := canonicalActionGrantDstSidecar(dst); action != nil && !slices.Contains(clearSidecars, id) {
			return fmt.Errorf("%w: grant_dst[%d] names a sidecar the clear grant_dst does not", ErrCanonicalActionDetailInvalid, i)
		}
	}
	return nil
}

// Opens action's sealed_detail with the key of the generation it names, which repoKeyAt answers (nil holds none),
// under the context action's own stored bytes derive in networkId's network (CanonicalActionDetailSealContext), and
// holds it to the action. nil with no error for an action that carries none. See CanonicalActionDetailOpener for the
// errors.
func OpenCanonicalActionDetail(action *StoredCanonicalAction, networkId Id, repoKeyAt func(generation uint64) *EvsRepoKey) (*protocol.CanonicalActionDetail, error) {
	if action == nil || action.Action == nil {
		return nil, fmt.Errorf("%w: no action", ErrCanonicalActionInvalid)
	}
	sealed := action.Action.GetSealedDetail()
	if len(sealed) == 0 {
		return nil, nil
	}
	sealContext, err := CanonicalActionDetailSealContext(networkId, action.Bytes)
	if err != nil {
		return nil, err
	}
	if repoKeyAt == nil {
		repoKeyAt = func(generation uint64) *EvsRepoKey { return nil }
	}
	detail := &protocol.CanonicalActionDetail{}
	if _, err := OpenConfigBody(sealed, sealContext, repoKeyAt, detail); err != nil {
		return nil, err
	}
	if err := CheckCanonicalActionDetail(action.Action, detail); err != nil {
		return nil, err
	}
	return detail, nil
}

// The stored action of a dial or route grant, or of an access request to a worker's port, its prefixes and ports
// sealed: clear holds the action's clear fields as NewCanonicalAction takes them, each final, and detail what its
// sealed_detail opens to, held to clear and sealed under repoKey, bound to clear's fields as stored in networkId's
// network (CanonicalActionDetailSealContext). The stored bytes are checked to derive what the detail was sealed to
// before they are answered. The caller's messages are not changed.
func NewSealedCanonicalAction(clear *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail, repoKey *EvsRepoKey, networkId Id, random io.Reader) (*StoredCanonicalAction, error) {
	return newSealedCanonicalAction(clear, detail, repoKey, networkId, random, CanonicalActionVersionKnown)
}

// NewSealedCanonicalAction, given which versions are known: CanonicalActionVersionKnown outside tests.
func newSealedCanonicalAction(clear *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail, repoKey *EvsRepoKey,
	networkId Id, random io.Reader, known func(version uint32) bool) (*StoredCanonicalAction, error) {
	if clear == nil {
		return nil, fmt.Errorf("%w: no action", ErrCanonicalActionInvalid)
	}
	if len(clear.GetSealedDetail()) != 0 {
		return nil, fmt.Errorf("%w: an action sealed already", ErrCanonicalActionInvalid)
	}
	if err := CheckCanonicalActionDetail(clear, detail); err != nil {
		return nil, err
	}
	clearBytes, err := canonicalActionClearBytes(clear)
	if err != nil {
		return nil, err
	}
	sealContext, err := CanonicalActionDetailSealContext(networkId, clearBytes)
	if err != nil {
		return nil, err
	}
	sealed, err := SealConfigBody(repoKey, sealContext, detail, random)
	if err != nil {
		return nil, err
	}
	action := proto.Clone(clear).(*protocol.CanonicalAction)
	action.SealedDetail = sealed
	stored, err := newCanonicalAction(action, known)
	if err != nil {
		return nil, err
	}
	// every reader derives its context from the stored bytes, so they must give the one sealed under
	storedContext, err := CanonicalActionDetailSealContext(networkId, stored.Bytes)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(storedContext.Nonce, sealContext.Nonce) {
		return nil, fmt.Errorf("%w: the stored clear fields are not those the detail was sealed beside", ErrCanonicalActionInvalid)
	}
	return stored, nil
}

// This device's network and the config repo's keys KEYS installed (InstallConfigKeys), which a detail seals and opens
// under. ErrConfigSealGenerationMissing while none are installed: the device holds no generation.
func (self *Sidecar) actionDetailKeys() (Id, SidecarConfigKeys, error) {
	identity := self.currentIdentity()
	if identity == nil {
		return Id{}, nil, ErrSidecarNoIdentity
	}
	configKeys := self.configKeys()
	if configKeys == nil {
		return Id{}, nil, fmt.Errorf("%w: no config repo keys are installed", ErrConfigSealGenerationMissing)
	}
	return identity.NetworkId, configKeys, nil
}

// What action's sealed_detail opens to on this device (CanonicalActionDetailOpener): the config repo's key of the
// generation it names, in this sidecar's network, under the context the action's own bytes derive, never one a caller
// makes (OpenCanonicalActionDetail). An approver's render opens through here (NewApprovalApprover), and a GrantActivate
// reader on the device does the same. With no config keys installed it answers ErrConfigSealGenerationMissing, so an
// approver lists deny alone.
func (self *Sidecar) OpenActionDetail(action *StoredCanonicalAction) (*protocol.CanonicalActionDetail, error) {
	if action == nil || action.Action == nil {
		return nil, fmt.Errorf("%w: no action", ErrCanonicalActionInvalid)
	}
	if len(action.Action.GetSealedDetail()) == 0 {
		return nil, nil
	}
	networkId, configKeys, err := self.actionDetailKeys()
	if err != nil {
		return nil, err
	}
	return OpenCanonicalActionDetail(action, networkId, configKeys.ConfigKeyAt)
}

// The stored action of clear with detail sealed in its sealed_detail on this device (CanonicalActionDetailSealer):
// under the config repo's current key, bound to clear's fields, which the caller has made final, in this sidecar's
// network (NewSealedCanonicalAction). With no config keys installed it seals nothing.
func (self *Sidecar) SealActionDetail(ctx context.Context, clear *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail) (*StoredCanonicalAction, error) {
	networkId, configKeys, err := self.actionDetailKeys()
	if err != nil {
		return nil, err
	}
	repoKey, err := configKeys.CurrentConfigKey(ctx)
	if err != nil {
		return nil, err
	}
	if repoKey == nil {
		return nil, fmt.Errorf("%w: no current config key", ErrConfigSealGenerationMissing)
	}
	return NewSealedCanonicalAction(clear, detail, repoKey, networkId, nil)
}
