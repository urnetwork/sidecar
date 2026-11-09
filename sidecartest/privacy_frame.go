// CC2 (§22.7): every TransferFrame through the exchange, and the rule each must keep: a frame to a peer
// is sealed, an encryptedTransferFrame and nothing beside it, or an ack, or the handshake's
// EncryptedControl carrier; a frame to ControlId, the platform, is read in the clear; and a frame from
// ControlId, a resident's (push_net.go), holds acks and hint fields alone (R-PROTO-8). The
// exchange taps frames with connect's exported API alone (net_connect.go), the way
// connect/transfer_encrypt_contract_test.go taps ControlId; a frame kind that needed connect's
// unexported state to classify would be an X9 row for the owner (Q-TEST-1), never a copied helper.
//
// Each frame's size is kept by pair, in the order the exchange carried them, which FI-24's equal frame
// sizes and S12 read.

package sidecartest

import (
	"bytes"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
)

type privacyPair struct {
	source      connect.Id
	destination connect.Id
}

// The application bytes a frame carries in the clear, each its own view, so a payload that is a
// compressed stream opens from its start. A sealed frame's are ciphertext, and none is returned.
func plaintextFrameMessages(frame []byte) [][]byte {
	transferFrame := &protocol.TransferFrame{}
	if err := proto.Unmarshal(frame, transferFrame); err != nil {
		return nil
	}
	messages := [][]byte{}
	if transferFrame.Frame != nil {
		messages = append(messages, transferFrame.Frame.MessageBytes)
	}
	if transferFrame.Pack != nil {
		for _, packFrame := range transferFrame.Pack.Frames {
			messages = append(messages, packFrame.MessageBytes)
		}
	}
	return messages
}

// Why a frame from source to destination breaks CC2's rule, or empty when it keeps it.
func unsealedFrameReason(source connect.Id, destination connect.Id, frame []byte) string {
	if destination == connect.ControlId {
		return ""
	}
	if source == connect.ControlId {
		return controlFrameReason(frame)
	}
	transferFrame := &protocol.TransferFrame{}
	if err := proto.Unmarshal(frame, transferFrame); err != nil {
		return fmt.Sprintf("a frame that does not parse: %v", err)
	}
	switch {
	case 0 < len(transferFrame.EncryptedTransferFrame):
		if transferFrame.Pack != nil || transferFrame.Ack != nil || transferFrame.Frame != nil {
			return "a sealed frame carrying plaintext beside its seal"
		}
		return ""
	case transferFrame.Frame != nil:
		return fmt.Sprintf("a plaintext %s frame", transferFrame.Frame.MessageType)
	case transferFrame.Pack != nil:
		if transferFrame.Ack != nil {
			return "a plaintext pack with an ack"
		}
		for _, packFrame := range transferFrame.Pack.Frames {
			if packFrame.MessageType != protocol.MessageType_TransferEncryptedControl {
				return fmt.Sprintf("a plaintext pack holding a %s frame", packFrame.MessageType)
			}
		}
		if contractFrame := transferFrame.Pack.ContractFrame; contractFrame != nil && contractFrame.MessageType != protocol.MessageType_TransferContract {
			return fmt.Sprintf("a plaintext pack whose contract frame is a %s", contractFrame.MessageType)
		}
		// the handshake's carrier: EncryptedControl alone, beside the contract that admits it
		return ""
	case transferFrame.Ack != nil:
		return ""
	}
	return "a frame that is neither sealed, an ack nor the handshake"
}

// CC2: one frame through the exchange, copied, since the sender's pool owns the original. A frame to a
// peer that is not sealed is a finding.
func (self *PrivacyCapture) AddFrame(source connect.Id, destination connect.Id, frame []byte) {
	name := fmt.Sprintf("frame %s to %s", source, destination)
	reason := unsealedFrameReason(source, destination, frame)
	messages := plaintextFrameMessages(frame)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	pair := privacyPair{source: source, destination: destination}
	if self.frameSizes == nil {
		self.frameSizes = map[privacyPair][]int{}
	}
	self.frameSizes[pair] = append(self.frameSizes[pair], len(frame))
	self.items = append(self.items, &PrivacyItem{Class: PrivacyClassFrame, Name: name, Body: bytes.Clone(frame)})
	for index, message := range messages {
		self.items = append(self.items, &PrivacyItem{Class: PrivacyClassFrame, Name: fmt.Sprintf("%s message %d", name, index), Body: bytes.Clone(message)})
	}
	if reason != "" {
		self.ruleFindings = append(self.ruleFindings, &PrivacyFinding{
			Needle:     name,
			NeedleKind: privacyNeedleUnsealed,
			Class:      PrivacyClassFrame,
			Source:     name,
			Form:       reason,
		})
	}
}

// The size of each frame from source to destination, in the order the exchange carried them.
func (self *PrivacyCapture) FrameSizes(source connect.Id, destination connect.Id) []int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]int{}, self.frameSizes[privacyPair{source: source, destination: destination}]...)
}
