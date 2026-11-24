//go:build !sidecar_http

// §17.7.1's watch rides a data-class contract alone (owner decision 778; §6.11, D-PROTO-18): step 6 refuses
// DNS_SD_WATCH on control, as it refuses every request outside the control class's fixed set, drops its result there,
// and passes both on data; and no Service-mode source, an edge or a share's FriendsAndFamily path, may send either.

package sidecar

import (
	"testing"

	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol"
)

func TestBridgeDiscoveryWatchRidesTheDataClassAlone(t *testing.T) {
	watch := uint32(protocol.MessageType_DNS_SD_WATCH)
	result := uint32(protocol.MessageType_DNS_SD_WATCH_RESULT)
	for _, class := range []connectprotocol.ContractClass{connectprotocol.ContractClass_ContractClassControl, connectprotocol.ContractClass(0)} {
		if verdict := contractClassAdmits(class, watch, 0, true); verdict != contractClassRefuse {
			t.Errorf("a watch on class %v: %v, want refused", class, verdict)
		}
		if verdict := contractClassAdmits(class, result, EnvelopeFlagResponse, true); verdict != contractClassDrop {
			t.Errorf("a watch's result on class %v: %v, want dropped", class, verdict)
		}
	}
	data := connectprotocol.ContractClass_ContractClassData
	if contractClassAdmits(data, watch, 0, false) != contractClassPass || contractClassAdmits(data, result, EnvelopeFlagResponse, false) != contractClassPass {
		t.Errorf("the watch does not pass on the data class")
	}
	for _, role := range []SubprotocolRole{SubprotocolRoleSidecar, SubprotocolRoleEdge} {
		if serviceMessageAdmits(role, watch, 0) || serviceMessageAdmits(role, result, EnvelopeFlagResponse) {
			t.Errorf("a Service-mode source may send the watch to role %v", role)
		}
	}
}
