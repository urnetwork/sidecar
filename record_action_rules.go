// §16.8's rules for a stored CanonicalAction, and its order row for a push's entries, on every leg.
//
// An approver refuses a CanonicalAction version it does not know (§16.8, §22.5's §16 row), so the versions this build
// knows are a set, never a maximum: version 3, access_request's, arrived at M6 and version 2, field 37's, at M10, in
// either order (§23.4's M3 row). Only version 2 may carry field 37, and versioning 0 (on) encodes as absent, so no
// version is ever read from a field's presence.
//
// The owner's answer to record-m2-01-canonical-action-detail (QD-740; owner decision 220) seals what a dial or route
// grant's clear fields may not show a server. Version 4 is such a grant's, kind bridge_forward's: kind, version and
// scope, fields 8, 10, 11, 28 and 29, and sealed_detail, 38, a CanonicalActionDetail holding its prefixes and ports
// under §7.9's sealed-body format, so its clear grant_dst names subjects alone, never an ip: prefix or a port. Every
// version-4 action carries one, a template's included, so no such grant reads as one to every port.
// Version 3 is kind access_request alone, in fields 8, 10, 11, 14, 26 and 29 with its port and port text in field 38
// the same way (16.11), 27 leaving its clear set. Field 38 is set in no other version, and bridge_forward takes no
// other version than 4: the shape before the answer, a version-1 forward with its port in the clear, is refused by
// every parser, as NewCanonicalAction builds none. At every version a clear grant_dst names its destination alone,
// since a GrantActivate carries a prefix or a port only sealed (owner decision 220), so no parser admits what the
// builder refuses.
//
// Which fields each other kind fills, and which of them a GrantActivate or a gate may carry, are MCP-M3-02's kind
// table, and the per-path allowlist ACL's and the gates' (protos-services-canonical-action); this file holds what is
// true of every action, and the shapes a row cannot say: an egress_change's exits and its requirement of default
// egress, require_default_egress, field 41 (QD-1060), which its mode decides (QD-799's egress_mode, field 39), and a
// share's network, share_network_id, field 40 (QD-820), which a dial or route
// grant alone names, as a network's id; what the grant's destinations may then be is ACL's (ParseAclGrantAction).
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"cmp"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// A CanonicalAction of a version this build does not know, which an approver refuses rather than renders
	// (§16.8).
	ErrCanonicalActionVersionUnknown = errors.New("canonical action version unknown")
	// A CanonicalAction that breaks a rule of its version: an unknown or zero kind, a field its version does not
	// set, a field this build cannot name, or a value a field cannot hold.
	ErrCanonicalActionInvalid = errors.New("canonical action invalid")
)

// CanonicalAction's field numbers the rules name (§16.8's fence), and the versions that seal a detail.
const (
	canonicalActionFieldKind         = 1
	canonicalActionFieldGrantDst     = 10
	canonicalActionFieldVersion      = 12
	canonicalActionFieldScope        = 13
	canonicalActionFieldVersioning   = 37
	canonicalActionFieldSealedDetail = 38
	canonicalActionFieldEgressMode   = 39
	// A share's other network (§8.11; QD-820), on a dial or route grant.
	canonicalActionFieldShareNetworkId = 40
	// An egress_change's requirement of default egress, under exits alone (QD-1060).
	canonicalActionFieldRequireDefaultEgress = 41

	// field 37's version, versioning at format 2 (§11.7; RECORD-M10-03): the one version that may carry it.
	canonicalActionVersionVersioning = 2
	// access_request's version (16.11).
	canonicalActionVersionAccessRequest = 3
	// A dial or route grant's version, its prefixes and ports in sealed_detail (QD-740).
	canonicalActionVersionSealedGrant = 4
)

// §16.8's limits on a CanonicalAction, which every builder, approver, spender and gate holds alike (QD-702): the
// protocol's values, so changing one is a protocol change no deployment makes on one side alone. The package-level
// rules read DefaultCanonicalActionSettings(); threading each side's own instance through them is the review phase's
// settings sweep (QD-706).
type CanonicalActionSettings struct {
	// A preview, rendered as untrusted text: 2 KiB (§16.8).
	PreviewMaxByteCount int
}

// §16.8's values. A fresh value each call.
func DefaultCanonicalActionSettings() *CanonicalActionSettings {
	return &CanonicalActionSettings{
		PreviewMaxByteCount: 2 * 1024,
	}
}

// The fields a version-3 access_request may set (§16.8's version comment; 16.11; QD-740): kind, version and scope, and
// expires_millis, grant_dst, grant_allow, repo_id, target_sidecar_id, subject and sealed_detail, where its port rides.
var canonicalActionVersion3Fields = []protoreflect.FieldNumber{
	canonicalActionFieldKind, canonicalActionFieldVersion, canonicalActionFieldScope, 8, canonicalActionFieldGrantDst,
	11, 14, 26, 29, canonicalActionFieldSealedDetail,
}

// The fields a version-4 dial or route grant may set (owner decision 220; QD-740): kind, version and scope, and
// expires_millis, a subject-only grant_dst, grant_allow, rule_id, subject and sealed_detail, and a share's
// share_network_id (QD-820).
var canonicalActionVersion4Fields = []protoreflect.FieldNumber{
	canonicalActionFieldKind, canonicalActionFieldVersion, canonicalActionFieldScope, 8, canonicalActionFieldGrantDst,
	11, 28, 29, canonicalActionFieldSealedDetail, canonicalActionFieldShareNetworkId,
}

// The actions a version-4 grant asks: §8.4's names of dial and route.
var canonicalActionSealedGrantAllows = []string{"dial", "route"}

// Whether this build's approvers know a CanonicalAction version: 1 at M3, 3, access_request's, at M6 (MCP-M6-01),
// 4, a dial or route grant's sealed form (QD-740), and 2, field 37's versioning, at M10 (RECORD-M10-03), which the
// agent-config writes alone take; the evs write honors field 37 only under §19.11's format2 gate (EvsVersioningFor).
func CanonicalActionVersionKnown(version uint32) bool {
	switch version {
	case 1, canonicalActionVersionVersioning, canonicalActionVersionAccessRequest, canonicalActionVersionSealedGrant:
		return true
	}
	return false
}

// Whether a clear grant_dst entry names its destination alone, as a server may see it (owner decision 220): never an
// ip: prefix, and a sidecar with no port after its id. The rest of §8.4's grammar is ACL's to read (ParseAclGrantDst).
func canonicalActionGrantDstClear(dst string) bool {
	kind, value, _ := strings.Cut(dst, ":")
	switch kind {
	case "ip":
		return false
	case "sidecar":
		return !strings.Contains(value, ":")
	}
	return true
}

// Whether sealed has a sealed body's layout (config_seal.go): a generation, a nonce, and a ciphertext of whole padded
// blocks with its tag. Read without a key, so a detail written unsealed, or cut short, is refused by every parser,
// a server's included; whether it opens is the approver's and the reader's to find.
func canonicalActionSealedDetailLayout(sealed []byte) bool {
	if _, err := ConfigSealedGeneration(sealed); err != nil {
		return false
	}
	paddedByteCount := len(sealed) - configSealGenerationByteCount - chacha20poly1305.NonceSizeX - chacha20poly1305.Overhead
	return 0 < paddedByteCount && paddedByteCount%configSealPadByteCount == 0
}

// Holds an action to the rules of every version, given which versions are known: the version, then the kind, then
// what that version may set. known is CanonicalActionVersionKnown outside tests.
func canonicalActionCheck(action *protocol.CanonicalAction, known func(version uint32) bool) error {
	message := action.ProtoReflect()
	if len(message.GetUnknown()) != 0 {
		return fmt.Errorf("%w: a field this build cannot name", ErrCanonicalActionInvalid)
	}
	version := action.GetVersion()
	if !known(version) {
		return fmt.Errorf("%w: version %d", ErrCanonicalActionVersionUnknown, version)
	}
	kind := protocol.SidecarActionKind(action.GetKind())
	if _, ok := protocol.SidecarActionKind_name[int32(kind)]; !ok || kind == protocol.SidecarActionKind_SIDECAR_ACTION_KIND_UNSPECIFIED {
		return fmt.Errorf("%w: kind %d", ErrCanonicalActionInvalid, action.GetKind())
	}
	if row, ok := CanonicalActionFields(SidecarActionKind(kind)); ok && !slices.Contains(row.Versions, version) {
		// a version this build knows, but not one this kind takes: version 2 is field 37's, the agent-config writes'
		return fmt.Errorf("%w: kind %s at version %d", ErrCanonicalActionInvalid, kind, version)
	}
	accessRequest := kind == protocol.SidecarActionKind_SIDECAR_ACTION_KIND_ACCESS_REQUEST
	if accessRequest != (version == canonicalActionVersionAccessRequest) {
		return fmt.Errorf("%w: kind %s at version %d", ErrCanonicalActionInvalid, kind, version)
	}
	forward := kind == protocol.SidecarActionKind_SIDECAR_ACTION_KIND_FORWARD
	if forward != (version == canonicalActionVersionSealedGrant) {
		// the one kind whose grant is a dial or route grant, and it takes no version that seals nothing
		return fmt.Errorf("%w: kind %s at version %d", ErrCanonicalActionInvalid, kind, version)
	}
	sealedVersion := version == canonicalActionVersionAccessRequest || version == canonicalActionVersionSealedGrant
	setFields := []protoreflect.FieldNumber{}
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		setFields = append(setFields, field.Number())
		return true
	})
	for _, number := range setFields {
		if number == canonicalActionFieldVersioning && version != canonicalActionVersionVersioning {
			return fmt.Errorf("%w: field %d at version %d", ErrCanonicalActionInvalid, number, version)
		}
		if number == canonicalActionFieldSealedDetail && !sealedVersion {
			return fmt.Errorf("%w: field %d at version %d", ErrCanonicalActionInvalid, number, version)
		}
		if version == canonicalActionVersionAccessRequest && !slices.Contains(canonicalActionVersion3Fields, number) {
			return fmt.Errorf("%w: field %d at version 3", ErrCanonicalActionInvalid, number)
		}
		if version == canonicalActionVersionSealedGrant && !slices.Contains(canonicalActionVersion4Fields, number) {
			return fmt.Errorf("%w: field %d at version 4", ErrCanonicalActionInvalid, number)
		}
	}
	// at every version the clear fields hold no prefix or port (owner decision 220): the text stays out of the error,
	// which a log may carry (I-13)
	for _, dst := range action.GetGrantDst() {
		if !canonicalActionGrantDstClear(dst) {
			return fmt.Errorf("%w: a clear grant_dst naming a prefix or a port at version %d", ErrCanonicalActionInvalid, version)
		}
	}
	if sealedVersion {
		// what rides sealed reads as a sealed body: an approver that cannot open it refuses the action rather than
		// render it short (D-MCP-17)
		if sealed := action.GetSealedDetail(); len(sealed) != 0 && !canonicalActionSealedDetailLayout(sealed) {
			return fmt.Errorf("%w: a sealed_detail of %d bytes", ErrCanonicalActionInvalid, len(sealed))
		}
	}
	if version == canonicalActionVersionSealedGrant {
		// a dial or route grant always seals what it reaches, a template's included, so none reads as every port
		if len(action.GetSealedDetail()) == 0 {
			return fmt.Errorf("%w: a version-4 grant with no sealed_detail", ErrCanonicalActionInvalid)
		}
		for _, allow := range action.GetGrantAllow() {
			if !slices.Contains(canonicalActionSealedGrantAllows, allow) {
				return fmt.Errorf("%w: a version-4 grant asking more than dial or route", ErrCanonicalActionInvalid)
			}
		}
	}
	if DefaultCanonicalActionSettings().PreviewMaxByteCount < len(action.GetPreview()) {
		return fmt.Errorf("%w: a preview of %d bytes", ErrCanonicalActionInvalid, len(action.GetPreview()))
	}
	// A publish writes its resolved audience and mode (plan-MCP-wire-enum-numbers), and any action that sets one
	// sets a value acl.proto names.
	if audience := action.GetAudience(); audience != 0 {
		if _, ok := protocol.AclAudience_name[int32(audience)]; !ok {
			return fmt.Errorf("%w: audience %d", ErrCanonicalActionInvalid, audience)
		}
	}
	if appMode := action.GetAppMode(); appMode != 0 {
		if _, ok := protocol.AclAppMode_name[int32(appMode)]; !ok {
			return fmt.Errorf("%w: app_mode %d", ErrCanonicalActionInvalid, appMode)
		}
	}
	if kind == protocol.SidecarActionKind_SIDECAR_ACTION_KIND_EGRESS_CHANGE || action.GetEgressMode() != 0 ||
		action.GetRequireDefaultEgress() {
		if err := checkEgressChangeAction(action); err != nil {
			return err
		}
	}
	if shareNetworkId := action.GetShareNetworkId(); len(shareNetworkId) != 0 {
		// a share's network rides a dial or route grant alone (QD-820), as one network's id: the id stays out of the
		// errors, which a log may carry (I-13)
		if version != canonicalActionVersionSealedGrant {
			return fmt.Errorf("%w: share_network_id at version %d", ErrCanonicalActionInvalid, version)
		}
		if len(shareNetworkId) != recordIdByteCount || bytes.Equal(shareNetworkId, make([]byte, recordIdByteCount)) {
			return fmt.Errorf("%w: a share_network_id that is no network's id", ErrCanonicalActionInvalid)
		}
	}
	return nil
}

// Holds an action that sets egress_mode or require_default_egress to egress_change's shape (QD-799), a template's
// included: kind egress_change, a 16-byte subject, a mode bridge.proto names, and under exits the exits in grant_dst,
// sidecar:<id> entries or one tag:<id> alone, each id in 32 lowercase hex digits and none named twice, and maybe the
// requirement of default egress (QD-1060); under auto or none no grant_dst and no requirement. So no approver renders,
// and no spender takes, an egress change whose exits read two ways. The ids stay out of every error, which a log may
// carry (I-13).
func checkEgressChangeAction(action *protocol.CanonicalAction) error {
	if protocol.SidecarActionKind(action.GetKind()) != protocol.SidecarActionKind_SIDECAR_ACTION_KIND_EGRESS_CHANGE {
		return fmt.Errorf("%w: egress_mode or require_default_egress on kind %d", ErrCanonicalActionInvalid, action.GetKind())
	}
	if len(action.GetSubject()) != recordIdByteCount {
		return fmt.Errorf("%w: an egress change's subject of %d bytes", ErrCanonicalActionInvalid, len(action.GetSubject()))
	}
	grantDsts := action.GetGrantDst()
	switch mode := bridge.BridgeEgressMode(action.GetEgressMode()); mode {
	case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE:
		if len(grantDsts) != 0 {
			return fmt.Errorf("%w: an egress change of mode %s naming exits", ErrCanonicalActionInvalid, mode)
		}
		if action.GetRequireDefaultEgress() {
			// only an exits body carries the requirement (QD-1053)
			return fmt.Errorf("%w: an egress change of mode %s requiring default egress", ErrCanonicalActionInvalid, mode)
		}
		return nil
	case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS:
	default:
		return fmt.Errorf("%w: egress_mode %d", ErrCanonicalActionInvalid, action.GetEgressMode())
	}
	if len(grantDsts) == 0 {
		return fmt.Errorf("%w: an egress change to exits naming none", ErrCanonicalActionInvalid)
	}
	for i, dst := range grantDsts {
		kind, value, _ := strings.Cut(dst, ":")
		decoded, err := hex.DecodeString(value)
		switch {
		case kind != "sidecar" && kind != "tag":
			return fmt.Errorf("%w: an egress change's exit of kind %q", ErrCanonicalActionInvalid, kind)
		case err != nil || len(decoded) != recordIdByteCount || strings.ToLower(value) != value:
			return fmt.Errorf("%w: an egress change's exit that is no id in lowercase hex", ErrCanonicalActionInvalid)
		case kind == "tag" && len(grantDsts) != 1:
			return fmt.Errorf("%w: an egress change naming a tag beside other exits", ErrCanonicalActionInvalid)
		case slices.Contains(grantDsts[:i], dst):
			return fmt.Errorf("%w: an egress change naming an exit twice", ErrCanonicalActionInvalid)
		}
	}
	return nil
}

// §16.8's order row within a push: by writer_sidecar_id's bytes, then seq, whatever order the statement's changes take
// (RECORD.md section 5.3's position row). Ties, a fork inside one push, fall to the leaf, so every reader and the
// writer order a push alike.
func RecordCompareInPush(a *StoredRecordHeader, b *StoredRecordHeader) int {
	if order := bytes.Compare(a.Header.GetWriterSidecarId(), b.Header.GetWriterSidecarId()); order != 0 {
		return order
	}
	if order := cmp.Compare(a.Header.GetSeq(), b.Header.GetSeq()); order != 0 {
		return order
	}
	aLeaf := a.LeafHash()
	bLeaf := b.LeafHash()
	return bytes.Compare(aLeaf[:], bLeaf[:])
}

// Sorts a push's entries into §16.8's order, in place.
func RecordOrderInPush(headers []*StoredRecordHeader) {
	slices.SortStableFunc(headers, RecordCompareInPush)
}

// Whether a push's entries already stand in §16.8's order, as a reader holds a received push to it.
func RecordInPushOrder(headers []*StoredRecordHeader) bool {
	return slices.IsSortedFunc(headers, RecordCompareInPush)
}

// A CanonicalActionDetail that is not one its action may carry: empty, a port that is none, a prefix or a destination
// that does not read, a destination that names no port or prefix, or a sidecar the clear grant_dst does not name.
var ErrCanonicalActionDetailInvalid = errors.New("canonical action detail invalid")

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
