//go:build !js

// QD-772's golden bytes: a socket_listen's ApprovalRequest as stored, carrying its name at field 17 beside its local
// port or weight, and its action naming the socket by grant_dst alone, for a tls/ name and for an application name's
// token path under a synthetic K_sock, in testdata/record/listen_request.json. The js leg opens no files, so these
// stay off it.

package sidecar

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var updateListenRequestVectors = flag.Bool("update-listen-request-vectors", false,
	"rewrite testdata/record/listen_request.json")

const testListenRequestVectorsPath = "testdata/record/listen_request.json"

// One listen's request: its name, the grant_dst its action carries, both as stored, and request_sha256, in lowercase
// hex.
type testListenRequestVector struct {
	Name          string `json:"name"`
	SocketName    string `json:"socket_name"`
	GrantDst      string `json:"grant_dst"`
	Action        string `json:"action"`
	Request       string `json:"request"`
	RequestSha256 string `json:"request_sha256"`
}

// testdata/record/listen_request.json: the inputs every vector shares, then the vectors.
type testListenRequestVectors struct {
	Comment   string                     `json:"comment"`
	NetworkId string                     `json:"network_id"`
	SocketKey string                     `json:"socket_key"`
	Requests  []*testListenRequestVector `json:"requests"`
}

// The synthetic network and K_sock an application name is blinded under.
var (
	testListenVectorNetworkId = Id(bytes.Repeat([]byte{0x31}, 16))
	testListenVectorSocketKey = bytes.Repeat([]byte{0x5a}, socketKeyByteCount)
)

// The vectors as this build makes them from fixed inputs: each action through NewCanonicalAction, each request's
// fixed fields and detail deterministically encoded, and each request parsing back to its detail.
func testComputeListenRequestVectors(t *testing.T) *testListenRequestVectors {
	t.Helper()
	keys, err := NewSocketKeys(testListenVectorNetworkId, testListenVectorSocketKey)
	if err != nil {
		t.Fatal(err)
	}
	vectors := &testListenRequestVectors{
		Comment: "QD-772's vectors: a socket_listen's ApprovalRequest as stored, its name at field 17 beside its local " +
			"port or weight, and its CanonicalAction naming the socket by its one grant_dst entry alone, sock:<name> for " +
			"a tls/ name and sock:<token path in hex> for an application name under K_sock socket_key in network " +
			"network_id (§9.4). Every other request field is fixed. go test -run TestListenRequestVectors " +
			"-update-listen-request-vectors rewrites this file.",
		NetworkId: hex.EncodeToString(testListenVectorNetworkId.Bytes()),
		SocketKey: hex.EncodeToString(testListenVectorSocketKey),
	}
	for _, c := range []struct {
		name   string
		detail *SidecarActionDetail
	}{
		{name: "tls", detail: &SidecarActionDetail{SocketName: "tls/443/blog", Weight: 100}},
		{name: "application", detail: &SidecarActionDetail{SocketName: "db/primary", LocalPort: 15432}},
	} {
		grantDst, err := SocketListenGrantDst(c.detail.SocketName, keys)
		if err != nil {
			t.Fatal(err)
		}
		action := buildTestAction(t, &protocol.CanonicalAction{Kind: uint32(SidecarActionListen), GrantDst: []string{grantDst}})
		approvalId := Id(bytes.Repeat([]byte{0x22}, 16))
		actionId := action.ActionId(approvalId)
		payloadSha256 := action.PayloadSha256()
		requestBytes := testRecordStored(t, &protocol.ApprovalRequest{
			ApprovalId: approvalId.Bytes(), ActionId: actionId[:], RunId: bytes.Repeat([]byte{0x77}, 16),
			AgentId: bytes.Repeat([]byte{0x88}, 16), CanonicalAction: action.Bytes, PayloadSha256: payloadSha256[:],
			Summary: "listen for the service", Risk: uint32(SidecarRiskNormal),
			RequesterSidecarId: bytes.Repeat([]byte{0x55}, 16), Approvers: [][]byte{bytes.Repeat([]byte{0x66}, 16)},
			NotAfterMillis: 1762387200000, Version: 1,
			SocketName: c.detail.SocketName, LocalPort: c.detail.LocalPort, Weight: c.detail.Weight,
		})
		request, err := ParseStoredApprovalRequest(requestBytes)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !request.Detail().Equal(c.detail) {
			t.Fatalf("%s: the request parses to %+v", c.name, request.Detail())
		}
		requestSha256 := request.Sha256()
		vectors.Requests = append(vectors.Requests, &testListenRequestVector{
			Name:          c.name,
			SocketName:    c.detail.SocketName,
			GrantDst:      grantDst,
			Action:        hex.EncodeToString(action.Bytes),
			Request:       hex.EncodeToString(requestBytes),
			RequestSha256: hex.EncodeToString(requestSha256[:]),
		})
	}
	return vectors
}

// The file's bytes are what this build makes of the same inputs today; each request parses, carries its name at
// field 17 once and in no action byte, its action naming the socket as the vector's grant_dst, which the network's
// K_sock derives for an application name; and each request_sha256 recomputes over the stored bytes.
func TestListenRequestVectors(t *testing.T) {
	if *updateListenRequestVectors {
		encoded := &bytes.Buffer{}
		encoder := json.NewEncoder(encoded)
		// the comment's grammar keeps its angle brackets
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(testComputeListenRequestVectors(t)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(testListenRequestVectorsPath, encoded.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := os.ReadFile(testListenRequestVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	vectors := &testListenRequestVectors{}
	if err := json.Unmarshal(encoded, vectors); err != nil {
		t.Fatal(err)
	}
	computed := testComputeListenRequestVectors(t)
	if vectors.NetworkId != computed.NetworkId || vectors.SocketKey != computed.SocketKey || len(vectors.Requests) != len(computed.Requests) {
		t.Fatalf("the file's inputs or vector count differ from this build's")
	}
	ring, err := NewSocketKeyRing(testListenVectorNetworkId, &protocol.SocketKeyFile{CurrentKey: testListenVectorSocketKey}, DefaultSocketKeyRingSettings())
	if err != nil {
		t.Fatal(err)
	}
	for i, vector := range vectors.Requests {
		if *vector != *computed.Requests[i] {
			t.Errorf("%s: this build now makes %+v", vector.Name, computed.Requests[i])
		}
		requestBytes := testRecordHex(t, vector.Request)
		request, err := ParseStoredApprovalRequest(requestBytes)
		if err != nil {
			t.Errorf("%s: %v", vector.Name, err)
			continue
		}
		if !bytes.Equal(request.Action.Bytes, testRecordHex(t, vector.Action)) || request.Request.GetSocketName() != vector.SocketName {
			t.Errorf("%s: the request carries another action or name", vector.Name)
		}
		nameRecord := protowire.AppendString(protowire.AppendTag(nil, 17, protowire.BytesType), vector.SocketName)
		if bytes.Count(requestBytes, nameRecord) != 1 || bytes.Contains(request.Action.Bytes, []byte(vector.SocketName)) != (vector.Name == "tls") {
			t.Errorf("%s: the name is not field 17's once, or shows in the action where it may not", vector.Name)
		}
		if grantDst := request.Action.Action.GetGrantDst(); len(grantDst) != 1 || grantDst[0] != vector.GrantDst {
			t.Errorf("%s: the action's grant_dst %v", vector.Name, grantDst)
		}
		if err := checkSocketListenName(request.Action.Action, vector.SocketName, ring); err != nil {
			t.Errorf("%s: the name does not read under the vector's K_sock: %v", vector.Name, err)
		}
		if requestSha256 := ApprovalRequestSha256(requestBytes); hex.EncodeToString(requestSha256[:]) != vector.RequestSha256 {
			t.Errorf("%s: request_sha256 %x", vector.Name, requestSha256)
		}
		// a re-encoding is no stored request: the hash covers the bytes as stored
		recoded, err := proto.Marshal(request.Request)
		if err != nil {
			t.Fatal(err)
		}
		if requestSha256 := ApprovalRequestSha256(recoded); !bytes.Equal(recoded, requestBytes) && hex.EncodeToString(requestSha256[:]) == vector.RequestSha256 {
			t.Errorf("%s: a re-encoding hashes as the stored request", vector.Name)
		}
	}
}
