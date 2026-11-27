//go:build !ios_extension && !sidecar_http && !js

// The network acknowledgments' seam for the external tests (package sidecar_test), which build a writer, its state and
// its head on T2's fake api and cannot reach the act's parts: the act and the removal on parts a test world holds, as
// Sidecar.AckNetworkDisclosure builds them, and a block's entries judged at a state. Tests only.

package sidecar

import (
	"context"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The parts an act runs on: the acting device and its signer, the writer, its verified state and the head it saves on,
// and the texts.
type NetworkDisclosureWriterForTest struct {
	SidecarId Id
	// Signs a DisclosureAck's body as the device's identity key would.
	Sign     func(body []byte) (*bridge.Signed, error)
	Writer   *ConfigWriter
	State    *ConfigState
	Tip      *ConfigHeadTip
	Registry *ComputeDisclosureRegistry
	Now      time.Time
}

// The actor these parts make.
func (self *NetworkDisclosureWriterForTest) actor() *computeNetworkDisclosureActor {
	return &computeNetworkDisclosureActor{
		sidecarId: self.SidecarId,
		sign:      self.Sign,
		writer:    self.Writer,
		state:     self.State,
		view:      &computeNetworkDisclosureConfig{state: self.State},
		tip:       self.Tip,
		registry:  self.Registry,
		now:       self.Now,
	}
}

// The network's acknowledgment on parts, as Sidecar.AckNetworkDisclosure makes it.
func AckNetworkDisclosureOnWriterForTest(ctx context.Context, parts *NetworkDisclosureWriterForTest, args *ComputeNetworkDisclosureAckArgs) (*bridge.AuthPin, error) {
	return parts.actor().ack(ctx, args)
}

// Its removal on parts, as Sidecar.RemoveNetworkDisclosure makes it.
func RemoveNetworkDisclosureOnWriterForTest(ctx context.Context, parts *NetworkDisclosureWriterForTest, args *ComputeNetworkDisclosureRemoveArgs) (*bridge.AuthPin, error) {
	return parts.actor().remove(ctx, args)
}

// statements, a block's disclosures, judged at state and covered at now under registry's newest policy, as a device
// whose verified state is state judges them.
func JudgeNetworkDisclosuresForTest(state *ConfigState, statements []AclComputeDisclosure, registry *ComputeDisclosureRegistry, now time.Time) ([]*ComputeNetworkDisclosure, error) {
	disclosures := newComputeNetworkDisclosures(&computeNetworkDisclosuresArgs{
		registry: func() (*ComputeDisclosureRegistry, error) { return registry, nil },
		read: func() (computeNetworkDisclosureState, []AclComputeDisclosure, error) {
			return &computeNetworkDisclosureConfig{state: state}, statements, nil
		},
		now:      func() time.Time { return now },
		settings: registry.Settings(),
	})
	return disclosures.Entries(context.Background())
}
