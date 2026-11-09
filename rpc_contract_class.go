//go:build !sidecar_http

// Step 6 of the inline handler (rpc_subprotocol.go): the receiver's rule for a contract's class (§6.4's
// control contracts, §6.10; D-PROTO-18, D-PROTO-21; FS-21, FI-10). The contract gate issues any two
// admitted sidecars of one network a Network contract of class control with no reach grant (§8.10), so
// witnessing and remote search have a path no policy document can cut; this rule keeps that path from
// carrying anything else. It is the receiver's own, and trusts nothing of the gate's beyond the class C13
// sealed: the gate checks no message type.
//
// On control:
//
//   - requests: Hello, Ping, HeadCheck and HeadCheckProofRequest; and SEARCH, only at a sidecar that
//     advertises Hello feature bit 0, serving remote search (rpc_features.go);
//   - responses: their replies, HelloResult, Pong, HeadCheckResult and HeadCheckProof, SEARCH_RESULT, and
//     the Error any of them may be answered with, which carries a code and no data;
//   - any other request is refused PERMISSION_DENIED, a StreamOpen StreamReject{DENIED}, and anything
//     else, a response, a Cancel or a stream frame, dropped and counted.
//
// A class C13 left unset, from a contract older than the seals or a build that does not know the value,
// is read as control, the narrowest, so a contract the gate did not class carries no data. The class is
// read from each frame's Peer, never kept per peer, since a pair's contracts change. A response to a data
// RPC rides the reverse contract, which the gate classes data when the request's origin stands
// (plan-ACL-network-reply-contracts), so such a response on control is refused, the closed direction.
// ControlId's hints carry no contract and skip this step.
//
// Denying IP on control is C5's EgressHook (BRIDGE), which D-PROTO-18 also requires and FS-21 checks; no
// sender changes, since a client generation sends witness traffic on whatever contract connect holds.

package sidecar

import (
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol"
)

// What step 6 does with an envelope.
type contractClassVerdict int

const (
	// it passes
	contractClassPass contractClassVerdict = iota
	// a request refused PERMISSION_DENIED
	contractClassRefuse
	// a StreamOpen rejected DENIED
	contractClassRejectStream
	// dropped unanswered: a response, a Cancel or a stream frame
	contractClassDrop
)

// Whether a class carries only §6.4's control exchanges: control itself, and unset, read as the
// narrowest. Data passes everything; a value this build does not know connect reports as unset.
func contractClassControl(class connectprotocol.ContractClass) bool {
	return class != connectprotocol.ContractClass_ContractClassData
}

// Step 6's rule for one envelope on a contract of class, at a receiver that serves remote search or not
// (Hello feature bit 0, as this side advertises it). See the file header.
func contractClassAdmits(class connectprotocol.ContractClass, messageType uint32, flags uint32, servesSearch bool) contractClassVerdict {
	if !contractClassControl(class) {
		return contractClassPass
	}
	if flags&EnvelopeFlagResponse != 0 {
		switch protocol.MessageType(messageType) {
		case protocol.MessageType_HELLO_RESULT, protocol.MessageType_PONG,
			protocol.MessageType_HEAD_CHECK_RESULT, protocol.MessageType_HEAD_CHECK_PROOF,
			protocol.MessageType_SEARCH_RESULT, protocol.MessageType_ERROR:
			return contractClassPass
		}
		return contractClassDrop
	}
	switch protocol.MessageType(messageType) {
	case protocol.MessageType_HELLO, protocol.MessageType_PING,
		protocol.MessageType_HEAD_CHECK, protocol.MessageType_HEAD_CHECK_PROOF_REQUEST:
		return contractClassPass
	case protocol.MessageType_SEARCH:
		if servesSearch {
			return contractClassPass
		}
	case protocol.MessageType_STREAM_OPEN:
		return contractClassRejectStream
	}
	if flags&EnvelopeFlagNoReply != 0 {
		return contractClassDrop
	}
	return contractClassRefuse
}
