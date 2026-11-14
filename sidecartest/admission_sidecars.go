// Running Sidecars in an admission world: the world's network is any FakeApi's on the Net's cluster, so a Sidecar the Net
// enrolls in it (AddSidecarIn, TestInstance.AddSidecarIn) reads its log through GET /network/config/projection as a
// device does, and these give what such a Sidecar's config follower needs beside it: the config repo's heads, which
// stand in for the head reader over evs, and its admission, signed by a device of the world from the identity the
// Sidecar holds, whose key never leaves its keychain.

package sidecartest

import (
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The network's config repo main ref in memory, as a follower's head reader.
func (self *AdmissionNet) Heads() *FakeConfigHeads {
	return self.heads
}

// Lands a SidecarAdmit of a running Sidecar's identity under memberId, signed by signer, an untagged member device of
// that member with capabilities, and applies it on every reader.
func (self *AdmissionNet) AdmitSidecar(signer *AdmissionDevice, identity *sidecar.SidecarIdentity, memberId sidecar.Id, capabilities uint32) sidecar.ConfigVerdict {
	self.t.Helper()
	admit := &protocol.SidecarAdmit{
		Header:            self.Header(),
		NetworkId:         self.networkId.Bytes(),
		SidecarId:         identity.SidecarId.Bytes(),
		IdentityPublicKey: identity.IdentityPublicKey,
		IdentityAlg:       "ed25519",
		MemberId:          memberId.Bytes(),
		Capabilities:      capabilities,
	}
	return self.MustLand(self.Sign(signer, bridge.SignedType_SIGNED_SIDECAR_ADMIT, admit))
}
