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
// What the seal is bound to is the caller's to give, a ConfigSealContext. A config record's is its signed type and
// its header's network id and nonce, and a CanonicalAction has no header: it is built and approved before any
// GrantActivate carries it. Which values stand in their place is question canonical-action-detail-seal-context, so
// nothing here derives one, and no daemon, approver or reader seals or opens a detail in production until it is
// answered: a version-4 request shows refused on every approver's device, the closed direction.
//
// EvsRepoKey.DeriveKey runs testHookSecret at the statement key. Package-level functions are safe for concurrent use.
// On every leg but the ios_extension legs, whose forwarding role builds and approves nothing.

package sidecar

import (
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
// detail names, under what the detail is sealed to. nil with no error for an action that carries none;
// ErrConfigSealGenerationMissing while the device lacks the generation; ErrConfigSealInvalid or
// ErrCanonicalActionDetailInvalid for one that does not open or is not its action's. Safe for concurrent use.
type CanonicalActionDetailOpener interface {
	OpenActionDetail(action *StoredCanonicalAction) (*protocol.CanonicalActionDetail, error)
}

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

// Seals detail for an action's sealed_detail under repoKey's generation, bound to context, with a nonce from random
// (crypto/rand's reader when nil). The detail is checked alone here, and against its action where the action is
// built (NewSealedCanonicalAction).
func SealCanonicalActionDetail(repoKey *EvsRepoKey, context *ConfigSealContext, detail *protocol.CanonicalActionDetail, random io.Reader) ([]byte, error) {
	if err := CheckCanonicalActionDetail(nil, detail); err != nil {
		return nil, err
	}
	return SealConfigBody(repoKey, context, detail, random)
}

// Opens action's sealed_detail with the key of the generation it names, which repoKeyAt answers, under context, and
// holds it to the action. nil with no error for an action that carries none. See CanonicalActionDetailOpener for the
// errors.
func OpenCanonicalActionDetail(action *StoredCanonicalAction, context *ConfigSealContext, repoKeyAt func(generation uint64) *EvsRepoKey) (*protocol.CanonicalActionDetail, error) {
	if action == nil || action.Action == nil {
		return nil, fmt.Errorf("%w: no action", ErrCanonicalActionInvalid)
	}
	sealed := action.Action.GetSealedDetail()
	if len(sealed) == 0 {
		return nil, nil
	}
	detail := &protocol.CanonicalActionDetail{}
	if _, err := OpenConfigBody(sealed, context, repoKeyAt, detail); err != nil {
		return nil, err
	}
	if err := CheckCanonicalActionDetail(action.Action, detail); err != nil {
		return nil, err
	}
	return detail, nil
}

// The stored action of a dial or route grant, or of an access request to a worker's port, its prefixes and ports
// sealed: clear holds the action's clear fields as NewCanonicalAction takes them, and detail what its sealed_detail
// opens to, held to clear and sealed under repoKey in context. The caller's messages are not changed.
func NewSealedCanonicalAction(clear *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail, repoKey *EvsRepoKey, context *ConfigSealContext, random io.Reader) (*StoredCanonicalAction, error) {
	return newSealedCanonicalAction(clear, detail, repoKey, context, random, CanonicalActionVersionKnown)
}

// NewSealedCanonicalAction, given which versions are known: CanonicalActionVersionKnown outside tests.
func newSealedCanonicalAction(clear *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail, repoKey *EvsRepoKey,
	context *ConfigSealContext, random io.Reader, known func(version uint32) bool) (*StoredCanonicalAction, error) {
	if clear == nil {
		return nil, fmt.Errorf("%w: no action", ErrCanonicalActionInvalid)
	}
	if len(clear.GetSealedDetail()) != 0 {
		return nil, fmt.Errorf("%w: an action sealed already", ErrCanonicalActionInvalid)
	}
	if err := CheckCanonicalActionDetail(clear, detail); err != nil {
		return nil, err
	}
	sealed, err := SealCanonicalActionDetail(repoKey, context, detail, random)
	if err != nil {
		return nil, err
	}
	action := proto.Clone(clear).(*protocol.CanonicalAction)
	action.SealedDetail = sealed
	return newCanonicalAction(action, known)
}
