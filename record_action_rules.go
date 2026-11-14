// §16.8's rules for a stored CanonicalAction, and its order row for a push's entries, on every leg.
//
// An approver refuses a CanonicalAction version it does not know (§16.8, §22.5's §16 row), so the versions this build
// knows are a set, never a maximum: version 3, access_request's, arrives at M6 and version 2, field 37's, at M10, in
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
// true of every action, and the one shape a row cannot say: an egress_change's exits, which its mode decides
// (QD-799's egress_mode, field 39).
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"cmp"
	"encoding/hex"
	"errors"
	"fmt"
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
// expires_millis, a subject-only grant_dst, grant_allow, rule_id, subject and sealed_detail.
var canonicalActionVersion4Fields = []protoreflect.FieldNumber{
	canonicalActionFieldKind, canonicalActionFieldVersion, canonicalActionFieldScope, 8, canonicalActionFieldGrantDst,
	11, 28, 29, canonicalActionFieldSealedDetail,
}

// The actions a version-4 grant asks: §8.4's names of dial and route.
var canonicalActionSealedGrantAllows = []string{"dial", "route"}

// Whether this build's approvers know a CanonicalAction version: 1 at M3, and 4, a dial or route grant's sealed
// form (QD-740). MCP-M6-01 adds 3 and RECORD-M10's carrier switch adds 2, each with its rules below already in
// force.
func CanonicalActionVersionKnown(version uint32) bool {
	switch version {
	case 1, canonicalActionVersionSealedGrant:
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
		if number == canonicalActionFieldVersioning && version != 2 {
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
	if kind == protocol.SidecarActionKind_SIDECAR_ACTION_KIND_EGRESS_CHANGE || action.GetEgressMode() != 0 {
		if err := checkEgressChangeAction(action); err != nil {
			return err
		}
	}
	return nil
}

// Holds an action that sets egress_mode to egress_change's shape (QD-799), a template's included: kind egress_change,
// a 16-byte subject, a mode bridge.proto names, and under exits the exits in grant_dst, sidecar:<id> entries or one
// tag:<id> alone, each id in 32 lowercase hex digits and none named twice; under auto or none no grant_dst. So no
// approver renders, and no spender takes, an egress change whose exits read two ways. The ids stay out of every error,
// which a log may carry (I-13).
func checkEgressChangeAction(action *protocol.CanonicalAction) error {
	if protocol.SidecarActionKind(action.GetKind()) != protocol.SidecarActionKind_SIDECAR_ACTION_KIND_EGRESS_CHANGE {
		return fmt.Errorf("%w: egress_mode on kind %d", ErrCanonicalActionInvalid, action.GetKind())
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
