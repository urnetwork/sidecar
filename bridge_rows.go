// BridgeRows, §17's id-only section of a base's AclRows (§8.8's AclRows.bridge, §17.8): each subject's egress mode, and
// nothing else. Gates read it to refuse Public contracts for a subject in exits or none (§8.10, D-BRIDGE-13); no
// prefix, address, port, map or alias is ever in it (D-BRIDGE-6, I-18).
//
// The section is log-derived, as the owner's answer to plan-BRIDGE-egress-mode-at-gates has it: every verifier applies
// each BridgeEgress entry's mode in log order over the rows it holds (bridgeRowsWithEgress, which the statement's
// rule calls), and a base's rows carry the same value at the fold (CompileBridgeRows, which ACL's CompileAcl calls for
// AclRows.bridge, C-05). Until BridgeEgress.mode lands no BridgeEgress takes effect (bridge_statement.go), so the
// section stays as the rows before held it, which is empty.
//
// One canonical encoding, so every reader hashes one rows_sha256: rows in subject order, one a subject, each mode
// exits or none. A subject in auto has no row: auto is every subject's default.
//
// Pure, with no clock, network or map order. On every leg, with no connect import. Nothing here creates, derives or
// unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The bytes are no BridgeRows a reader holds: a subject that is no 16-byte id, a mode a row never carries, or rows out
// of their one order.
var ErrBridgeRowsMalformed = errors.New("bridge rows malformed")

// Parses AclRows.bridge, strictly: rows as CompileBridgeRows writes them, and no field this build cannot name, since a
// row it skipped could be the one that closes a subject's egress. Empty bytes are the empty section.
func ParseBridgeRows(data []byte) (*bridge.BridgeRows, error) {
	rows := &bridge.BridgeRows{}
	if err := proto.Unmarshal(data, rows); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeRowsMalformed, err)
	}
	if len(rows.ProtoReflect().GetUnknown()) != 0 {
		return nil, fmt.Errorf("%w: a field this build cannot name", ErrBridgeRowsMalformed)
	}
	for i, row := range rows.GetEgress() {
		if err := bridgeCheckEgressRow(row); err != nil {
			return nil, fmt.Errorf("%w: egress[%d]: %w", ErrBridgeRowsMalformed, i, err)
		}
		if 0 < i && 0 <= bytes.Compare(rows.GetEgress()[i-1].GetSubject(), row.GetSubject()) {
			return nil, fmt.Errorf("%w: egress[%d] out of subject order", ErrBridgeRowsMalformed, i)
		}
	}
	return rows, nil
}

// One row as rows carry it: a 16-byte subject in exits or none.
func bridgeCheckEgressRow(row *bridge.BridgeEgressRow) error {
	if len(row.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("a field this build cannot name")
	}
	if len(row.GetSubject()) != len(Id{}) {
		return fmt.Errorf("a subject of %d bytes", len(row.GetSubject()))
	}
	if row.GetMode() != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS && row.GetMode() != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE {
		return fmt.Errorf("mode %d", row.GetMode())
	}
	return nil
}

// The section's one encoding.
func bridgeMarshalRows(rows *bridge.BridgeRows) ([]byte, error) {
	if len(rows.GetEgress()) == 0 {
		return nil, nil
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(rows)
}

// compile for §17's section (C-05): the BridgeRows bytes a base's AclRows.bridge carries, from the log-derived section
// at the head's folded_through, logRows, which is AclRows.bridge of the rows compile is given (ConfigCompileRows'
// AclStatements). Every BridgeEgress is a delta, so a head holds no egress record of its own and nothing is read from
// head but that there is one; it is taken so the call keeps CompileAcl's shape if a head file ever joins. The result
// is logRows in its one encoding, refused when logRows is no section a verifier could have folded.
func CompileBridgeRows(head *ConfigHead, logRows []byte) ([]byte, error) {
	if head == nil {
		return nil, fmt.Errorf("%w: no head", ErrBridgeRowsMalformed)
	}
	rows, err := ParseBridgeRows(logRows)
	if err != nil {
		return nil, err
	}
	return bridgeMarshalRows(rows)
}

// The section with subject's mode set, as one BridgeEgress entry changes it: exits or none writes the subject's row,
// and auto removes it.
func bridgeRowsWithEgress(data []byte, subject Id, mode bridge.BridgeEgressMode) ([]byte, error) {
	rows, err := ParseBridgeRows(data)
	if err != nil {
		return nil, err
	}
	next := &bridge.BridgeRows{}
	for _, row := range rows.GetEgress() {
		if !bytes.Equal(row.GetSubject(), subject.Bytes()) {
			next.Egress = append(next.Egress, row)
		}
	}
	switch mode {
	case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO:
	case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE:
		next.Egress = append(next.Egress, &bridge.BridgeEgressRow{Subject: subject.Bytes(), Mode: mode})
		slices.SortFunc(next.Egress, func(a *bridge.BridgeEgressRow, b *bridge.BridgeEgressRow) int {
			return bytes.Compare(a.GetSubject(), b.GetSubject())
		})
	default:
		return nil, fmt.Errorf("%w: mode %d", ErrBridgeRowsMalformed, mode)
	}
	return bridgeMarshalRows(next)
}

// The egress mode rows give one subject, a sidecar_id or a keyed atom: its row's, else auto.
func BridgeRowsEgressMode(rows *bridge.BridgeRows, subject Id) bridge.BridgeEgressMode {
	for _, row := range rows.GetEgress() {
		if bytes.Equal(row.GetSubject(), subject.Bytes()) {
			return row.GetMode()
		}
	}
	return bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO
}

// The egress modes this state's rows hold, with every BridgeEgress entry since the base applied: what §8.10's gate
// reads. An error is rows no verifier folded, which a gate treats as no answer and refuses on.
func (self *ConfigState) BridgeRows() (*bridge.BridgeRows, error) {
	return ParseBridgeRows(self.aclRows.GetBridge())
}
