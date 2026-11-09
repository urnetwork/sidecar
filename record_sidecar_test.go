//go:build !js

// Sidecar.Record (record_writer.go): none before the network and the identity are known, one record after, and that
// record failing closed until evs and the authorization state are bound: with no author to route to, a draft spools
// and nothing is sealed.

package sidecar

import (
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A Sidecar's record waits for its network and identity, is built once, and spools what it cannot route.
func TestSidecarRecordFailsClosedUntilBound(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	sidecar := &Sidecar{instance: instance, settings: validSidecarSettings()}
	if _, err := sidecar.Record(); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Fatalf("before enrollment: %v", err)
	}
	networkId := testNetworkId
	sidecar.networkId = &networkId
	if _, err := sidecar.Record(); !errors.Is(err, ErrSidecarNoIdentity) {
		t.Fatalf("before an identity: %v", err)
	}
	sidecar.identity = &SidecarIdentity{NetworkId: networkId, SidecarId: NewId(), IdentityPublicKey: make([]byte, 32)}
	record, err := sidecar.Record()
	if err != nil {
		t.Fatal(err)
	}
	again, err := sidecar.Record()
	if err != nil || again != record {
		t.Fatalf("a second record: %v", err)
	}
	refs, err := record.Writer().Append(&RecordDraft{
		Kind:      RecordKindNote,
		Source:    RecordSourceAgent,
		NoSession: true,
		Body:      &protocol.CoordinationBody{Text: "no author yet"},
	})
	if err != nil || len(refs) != 1 || !refs[0].Spooled {
		t.Fatalf("an unbound record's draft: %+v, %v", refs, err)
	}
	logIds, err := record.writer.chain.PendingLogIds()
	if err != nil || len(logIds) != 0 {
		t.Errorf("an unbound record sealed into %v: %v", logIds, err)
	}
}
