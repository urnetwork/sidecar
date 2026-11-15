//go:build !js && !ios && !android && !sdk_mobile_bind

// What FS-98's Team cases add to the CLI world (CORE-M6-04; §5.6's revocation, D-CORE-20, §7.9's scoped row, fs98.go):
// the network's self_admit, set on or off by a head its writer signs, and a member's OwnerConfirm of a device an admin
// admitted, so a member outside the AdminSet holds a consented host with self_admit off, where only an admin admits
// its devices; and a host's suspension as every reader holds it.

package sidecartest

import (
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Sets the network's self_admit by a head the writer, the owner's first device, signs, and waits for every host to
// apply it.
func (self *Fs98World) SetSelfAdmit(on bool) {
	self.t.Helper()
	mode := protocol.SelfAdmitMode_SELF_ADMIT_MODE_ON
	if !on {
		mode = protocol.SelfAdmitMode_SELF_ADMIT_MODE_OFF
	}
	self.admission.SetServiceSettings(&protocol.ServiceSettings{SelfAdmit: mode})
	if self.admission.State().SelfAdmit() != on {
		self.t.Fatalf("self_admit is not %t after the head set it", on)
	}
	self.Settle()
}

// The member's OwnerConfirm of device, an admin's admission under the member, signed by confirmer, a consented device
// of that member: it lands, the device is consented at every reader, and every host applies it.
func (self *Fs98World) OwnerConfirm(confirmer *AdmissionDevice, device *AdmissionDevice) {
	self.t.Helper()
	self.admission.MustLand(self.admission.Sign(confirmer, bridge.SignedType_SIGNED_OWNER_CONFIRM, self.admission.OwnerConfirm(device)))
	if !self.admission.Consented(device, device.MemberId) {
		self.t.Fatalf("%s is not consented after its member's OwnerConfirm", device.Name)
	}
	self.Settle()
}

// Whether an active Suspend names the host at the tip.
func (self *Fs98Host) Suspended() bool {
	return self.world.admission.State().Suspended(self.Device.SidecarId)
}
