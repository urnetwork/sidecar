//go:build ios_extension && !sidecar_http

// The forwarding role's shared call sites refuse app operations with no sidecar
// keystore, writer, stream store or search snapshot to consult.

package sidecar

import (
	"errors"
	"testing"
)

// A network id on an open host cannot start the sidecar or unlock a browser admission.
func TestForwardingLegKeepsTheSidecarUnenrolled(t *testing.T) {
	networkId := Id{1}
	host := &Sidecar{networkId: &networkId}
	host.lifecycle.state = SidecarStateUnenrolled
	host.reconcileOpen()
	if host.lifecycleState() != SidecarStateUnenrolled || host.runningGeneration() != nil {
		t.Fatal("the forwarding host started a sidecar generation")
	}
	if err := sidecarDecideAdmission(t.Context(), host, nil, nil, SidecarDecisionApprove, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarApprovalAuthority) {
		t.Errorf("device admission returned %v", err)
	}
	if err := host.checkBrowserAdmissionDependency(t.Context(), &browserAdmissionDependency{}); !errors.Is(err, ErrSidecarActRefused) {
		t.Errorf("pending browser statement returned %v", err)
	}
}

// Even an enabled search setting cannot retain a name or open a write checkpoint on the config reader's leg.
func TestForwardingLegReadsWithoutSearchOrWriteRecovery(t *testing.T) {
	repo := &EvsRepo{client: &EvsClient{}}
	repo.client.searchNames.Store(true)
	if observer := repo.searchReadObserver(&EvsReadArgs{}); observer != nil {
		t.Fatal("the extension installed a search observer")
	}
	if fields, err := repo.erasedBaseFields(t.Context(), nil, nil); fields != nil || !errors.Is(err, ErrEvsErased) {
		t.Errorf("opening an erased write base returned %v, %v", fields, err)
	}
}

// Shared callers cannot open a record, recover a capture, advance a writer or allocate a peer stream id.
func TestForwardingLegRefusesRecordAndPeerStreamStores(t *testing.T) {
	if record, err := (&Sidecar{}).Record(); record != nil || !errors.Is(err, ErrRecordStreamsUnavailable) {
		t.Fatalf("opening a record returned %v, %v", record, err)
	}
	writer := &recordWriter{}
	if err := writer.finishCaptureWithLock(); !errors.Is(err, ErrRecordStreamsUnavailable) {
		t.Errorf("recovering a capture returned %v", err)
	}
	if refs, err := writer.sealRoutes(nil, nil, nil); refs != nil || !errors.Is(err, ErrRecordStreamsUnavailable) {
		t.Errorf("sealing a capture returned %v, %v", refs, err)
	}
	if err := (&SidecarRecord{}).PrepareDirectWrites(t.Context()); !errors.Is(err, ErrRecordStreamsUnavailable) {
		t.Errorf("preparing direct writes returned %v", err)
	}
	if id, err := reserveStoredStreamIds(nil); id != 0 || !errors.Is(err, errSubprotocolClosed) {
		t.Errorf("reserving a peer stream id returned %d, %v", id, err)
	}
}
