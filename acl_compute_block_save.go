//go:build !sidecar_http && !ios_extension

// Saving a network with no document's block-alone compute record (DESIGN-COMPUTE §16.4; Appendix D's §7.9 ACL document
// rows; CACL-M12-03): the config head's compute.hujson, which its writers sign as they sign a document, through the
// config writer's publish, and which sets no reach. A network with a document keeps its block in the document, which
// SaveAclPolicy saves with the rest of it; a network's first document takes the record's block in, its text unchanged,
// and the save drops the record (PlanAclSave, AclComputeCarryRecord).
//
//	plan     the head with the record, refused beside a document and while the network's compute_policy feature is off,
//	         the record parsed and the head compiled, rows and projection, as every reader will compile it
//	sign     on the person's confirmation alone (D-CORE-13): never from MCP, a hook or an unconfirmed call; and only while
//	         the writer's head still holds the document and record the plan stood on, and the verified state its pin
//
// CTRUST-M12-02's network acknowledgments edit the record's disclosures through SetComputeBlockDisclosure and save it
// here. Not on the page Worker's leg, which writes no config head, nor the forwarding leg.

package sidecar

import (
	"bytes"
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The head that holds source as the block-alone record on head, checked as every reader will check it: refused beside a
// document, while state does not turn compute_policy on, for a record that does not parse, and for a head that does not
// compile.
func PlanAclComputeRecordSave(head *ConfigHead, state *ConfigState, source []byte) (*ConfigHead, error) {
	if head == nil || state == nil {
		return nil, fmt.Errorf("%w: no head or state", ErrAclCompile)
	}
	if head.File(ConfigHeadPolicyPath) != nil {
		return nil, ErrAclComputeRecordBesideDocument
	}
	if !state.AuthFeatureOn(AuthFeatureComputePolicy) {
		return nil, fmt.Errorf("%w: compute_policy is not on", ErrAuthFeatureOff)
	}
	if _, err := ParseAclComputeRecord(source); err != nil {
		return nil, err
	}
	next, err := head.WithFile(ConfigHeadComputePath, bytes.Clone(source))
	if err != nil {
		return nil, err
	}
	rows := ConfigCompileRowsOf(state)
	input, err := NewAclCompileInput(next, rows)
	if err != nil {
		return nil, err
	}
	if _, err := CompileAcl(input); err != nil {
		return nil, err
	}
	if _, err := CompileProjectionRows(next, rows); err != nil {
		return nil, err
	}
	return next, nil
}

// Saves source as the block-alone record through writer, on base, the head the person's confirmation stood on, while
// state is the verified state it was planned at: the writer's head must still hold base's document and record, and its
// state the same pin, else ErrAclSaveStale. Answers the base's pin.
func AclComputeRecordSave(ctx context.Context, writer *ConfigWriter, base *ConfigHead, state *ConfigState, source []byte, expected *ConfigHeadTip) (*bridge.AuthPin, error) {
	if writer == nil {
		return nil, ErrAclSaveUnconfirmed
	}
	if _, err := PlanAclComputeRecordSave(base, state, source); err != nil {
		return nil, err
	}
	return writer.publish(ctx, false, func(head *ConfigHead) (*ConfigHead, error) {
		current := writer.args.Client.State()
		if current == nil || !proto.Equal(state.Pin(), current.Pin()) {
			return nil, fmt.Errorf("%w: the signed network state changed", ErrAclSaveStale)
		}
		for _, path := range []string{ConfigHeadPolicyPath, ConfigHeadComputePath} {
			if !bytes.Equal(head.File(path), base.File(path)) {
				return nil, fmt.Errorf("%w: its %s file changed", ErrAclSaveStale, path)
			}
		}
		return head.WithFile(ConfigHeadComputePath, bytes.Clone(source))
	}, expected)
}

// Saves source as this network's block-alone compute record on this device's config writer, on the person's
// confirmation alone (D-CORE-13), as SaveAclPolicy saves a document. Answers the base's pin.
func (self *Sidecar) SaveComputeRecord(ctx context.Context, source []byte, origin SidecarActOrigin) (*bridge.AuthPin, error) {
	if origin != SidecarActConfirmed {
		return nil, ErrSidecarActMode
	}
	writer, state, tip, err := self.aclSaveContext(ctx, false)
	if err != nil {
		return nil, err
	}
	return AclComputeRecordSave(ctx, writer, tip.Head, state, source, tip)
}
