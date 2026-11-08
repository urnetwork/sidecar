// §16.8's rules for a stored CanonicalAction, and its order row for a push's entries, on every leg.
//
// An approver refuses a CanonicalAction version it does not know (§16.8, §22.5's §16 row), so the versions this build
// knows are a set, never a maximum: version 3, access_request's, arrives at M6 and version 2, field 37's, at M10, in
// either order (§23.4's M3 row). Only version 2 may carry field 37, and versioning 0 (on) encodes as absent, so no
// version is ever read from a field's presence. Version 3 is kind access_request alone, setting kind, version and
// scope and fields 8, 10, 11, 14, 26, 27 and 29 (16.11; protos-services-canonical-action). Which fields each other
// kind fills, and which of them a GrantActivate or a gate may carry, are MCP-M3-02's kind table, and the per-path
// allowlist ACL's and the gates' (protos-services-canonical-action); this file holds what is true of every action.
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A CanonicalAction of a version this build does not know, which an approver refuses rather than renders
	// (§16.8).
	ErrCanonicalActionVersionUnknown = errors.New("canonical action version unknown")
	// A CanonicalAction that breaks a rule of its version: an unknown or zero kind, a field its version does not
	// set, a field this build cannot name, or a value a field cannot hold.
	ErrCanonicalActionInvalid = errors.New("canonical action invalid")
)

// CanonicalAction's field numbers the rules name (§16.8's fence).
const (
	canonicalActionFieldKind       = 1
	canonicalActionFieldVersion    = 12
	canonicalActionFieldScope      = 13
	canonicalActionFieldVersioning = 37
	// §16.8's preview cap, rendered as untrusted text.
	canonicalActionPreviewMaxByteCount = 2 * 1024
)

// The fields a version-3 access_request may set (§16.8's version comment; 16.11): kind, version and scope, and
// expires_millis, grant_dst, grant_allow, repo_id, target_sidecar_id, target_port and subject.
var canonicalActionVersion3Fields = []protoreflect.FieldNumber{
	canonicalActionFieldKind, canonicalActionFieldVersion, canonicalActionFieldScope, 8, 10, 11, 14, 26, 27, 29,
}

// Whether this build's approvers know a CanonicalAction version: 1 at M3. MCP-M6-01 adds 3 and RECORD-M10's
// carrier switch adds 2, each with its rules below already in force.
func CanonicalActionVersionKnown(version uint32) bool {
	switch version {
	case 1:
		return true
	}
	return false
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
	if accessRequest != (version == 3) {
		return fmt.Errorf("%w: kind %s at version %d", ErrCanonicalActionInvalid, kind, version)
	}
	setFields := []protoreflect.FieldNumber{}
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		setFields = append(setFields, field.Number())
		return true
	})
	for _, number := range setFields {
		if number == canonicalActionFieldVersioning && version != 2 {
			return fmt.Errorf("%w: field %d at version %d", ErrCanonicalActionInvalid, number, version)
		}
		if version == 3 && !slices.Contains(canonicalActionVersion3Fields, number) {
			return fmt.Errorf("%w: field %d at version 3", ErrCanonicalActionInvalid, number)
		}
	}
	if canonicalActionPreviewMaxByteCount < len(action.GetPreview()) {
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
