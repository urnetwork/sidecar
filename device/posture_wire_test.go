// The posture reads config.proto's Delegation and DelegationRevoke by wire, since device may not link protocol
// (§4.4): this consumer of both holds the fixture's by-wire bodies, which the posture's tests sign and apply, to the
// bytes protocol's own encoder writes, every field set, so a field the posture reads cannot drift from the schema.

package device_test

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

func TestPostureReadsDelegationsAsConfigProtoWritesThem(t *testing.T) {
	header := &bridge.StatementHeader{
		NetworkId:  bytes.Repeat([]byte{0x01}, 16),
		At:         &bridge.AuthPin{Version: 7, Chain: bytes.Repeat([]byte{0x02}, 32)},
		Nonce:      bytes.Repeat([]byte{0x03}, 16),
		NotAfterMs: 1_800_000_000_000,
	}
	forward := &bridge.ForwardScope{
		ForwardSidecarId: bytes.Repeat([]byte{0x04}, 16), HostClientId: bytes.Repeat([]byte{0x05}, 16),
		HostClientPublicKey: bytes.Repeat([]byte{0x06}, 32),
	}
	pubkey, readerKey := bytes.Repeat([]byte{0x07}, 32), bytes.Repeat([]byte{0x08}, 1216)
	deterministic := proto.MarshalOptions{Deterministic: true}
	for _, scope := range []*bridge.ForwardScope{forward, nil} {
		want, err := deterministic.Marshal(&protocol.Delegation{Header: header, Pubkey: pubkey, ReaderXwingPublicKey: readerKey, Forward: scope})
		if err != nil {
			t.Fatal(err)
		}
		if got := device.PostureFixtureDelegationBodyForTest(header, pubkey, readerKey, scope); !bytes.Equal(got, want) {
			t.Errorf("a Delegation, forward %v: the fixture writes other bytes than config.proto's encoder", scope != nil)
		}
	}
	for _, sinceN := range []uint64{0, 9} {
		want, err := deterministic.Marshal(&protocol.DelegationRevoke{Header: header, DelegationId: bytes.Repeat([]byte{0x09}, 32), SinceN: sinceN})
		if err != nil {
			t.Fatal(err)
		}
		if got := device.PostureFixtureDelegationRevokeBodyForTest(header, bytes.Repeat([]byte{0x09}, 32), sinceN); !bytes.Equal(got, want) {
			t.Errorf("a DelegationRevoke, since_n %d: the fixture writes other bytes than config.proto's encoder", sinceN)
		}
	}
	// and the fields the posture reads by number are the schema's
	delegation := (&protocol.Delegation{}).ProtoReflect().Descriptor().Fields()
	revoke := (&protocol.DelegationRevoke{}).ProtoReflect().Descriptor().Fields()
	for _, field := range []struct {
		name   string
		number int32
		got    int32
	}{
		{name: "Delegation.header", number: 1, got: int32(delegation.ByName("header").Number())},
		{name: "Delegation.forward", number: 7, got: int32(delegation.ByName("forward").Number())},
		{name: "DelegationRevoke.header", number: 1, got: int32(revoke.ByName("header").Number())},
		{name: "DelegationRevoke.delegation_id", number: 2, got: int32(revoke.ByName("delegation_id").Number())},
		{name: "DelegationRevoke.since_n", number: 3, got: int32(revoke.ByName("since_n").Number())},
	} {
		if field.got != field.number {
			t.Errorf("%s is field %d, the posture reads %d", field.name, field.got, field.number)
		}
	}
}
