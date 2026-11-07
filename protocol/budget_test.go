// Bounds the design states on a message, held at each message's worst case, so a field added later that breaks one
// fails here rather than on the wire. Identifiers are the design's 16 B ids and 32 B hashes, and numbers the largest
// a varint holds, so these overstate what a real ticket or hint takes.

package protocol

import (
	"bytes"
	"math"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
)

const (
	testIdSize   = 16
	testHashSize = 32

	// §6.8: a hint is at most this, inside PushHint.hint.
	testHintBound = 256
	// §9.6's comments on SocketTicket and SignedSocketTicket.
	testTicketBound       = 370
	testSignedTicketBound = 512
	// §16.11: q/<tgt>/<rid>, padded to this.
	testNoticeBound = 256
	// §16.11's DirectoryNotice.decisions: at most the rule's 2.
	testNoticeDecisions = 2
)

// Stands for an identifier or hash of this size.
func testBytes(size int) []byte {
	return bytes.Repeat([]byte{0xFF}, size)
}

// What a message takes on the wire.
func testSize(t *testing.T, message proto.Message) int {
	encoded, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return len(encoded)
}

// A ticket with every field at its widest but the name and token path, which each test sets to its own limit.
func testTicket() *SocketTicket {
	return &SocketTicket{
		TicketId:              testBytes(testIdSize),
		NetworkId:             testBytes(testIdSize),
		ListenerClientId:      testBytes(testIdSize),
		ListenId:              testBytes(testIdSize),
		DialerClientId:        testBytes(testIdSize),
		DialerNetworkId:       testBytes(testIdSize),
		IssueTimeMillis:       math.MaxUint64,
		ExpireTimeMillis:      math.MaxUint64,
		PolicyVersion:         math.MaxUint64,
		GrantId:               testBytes(testIdSize),
		Backup:                true,
		GrantExpireTimeMillis: math.MaxUint64,
	}
}

// §9.6: a ticket fits with a 112-byte name or an 8-segment token path, and a signed one in StreamOpen.ticket.
func TestSocketTicketFitsItsBounds(t *testing.T) {
	named := testTicket()
	named.Name = strings.Repeat("n", 112)
	tokened := testTicket()
	tokened.NameToken = testBytes(8 * testIdSize)

	for _, ticket := range []*SocketTicket{named, tokened} {
		encoded, err := proto.Marshal(ticket)
		if err != nil {
			t.Fatal(err)
		}
		if len(encoded) > testTicketBound {
			t.Errorf("a ticket takes %d B, over %d", len(encoded), testTicketBound)
		}
		signed := &SignedSocketTicket{
			KeyId:     strings.Repeat("k", 64),
			Ticket:    encoded,
			Signature: testBytes(64),
		}
		if size := testSize(t, signed); size > testSignedTicketBound {
			t.Errorf("a signed ticket takes %d B, over %d", size, testSignedTicketBound)
		}
	}
}

// §6.8: PushHint.hint holds ids, kinds and versions, and is dropped when coalesced.
func TestHintsFitPushHint(t *testing.T) {
	cases := []struct {
		name    string
		message proto.Message
	}{
		{
			name:    "SocketHint",
			message: &SocketHint{Kind: SocketHintKind_SOCKET_HINT_DRAIN, ListenId: testBytes(testIdSize)},
		},
		{
			name: "GkmHint",
			message: &GkmHint{
				GroupId: testBytes(testIdSize),
				Epoch:   math.MaxUint64,
				Kind:    GkmHintKind_GKM_HINT_WRAP_PENDING,
				// d: and a delegation_id, the longest recipient 10.6 names, its hex form the longest it could take.
				Recipient: testBytes(2 + 2*testHashSize),
			},
		},
		{
			name: "EvsHeadChanged",
			message: &EvsHeadChanged{
				RefId:   testBytes(testIdSize),
				Version: math.MaxUint64,
				Chain:   testBytes(testHashSize),
				PushId:  testBytes(testIdSize),
			},
		},
	}
	for _, c := range cases {
		if size := testSize(t, c.message); size > testHintBound {
			t.Errorf("%s takes %d B, over %d", c.name, size, testHintBound)
		}
	}
}

// §16.11: a notice names up to the rule's two approvals and still pads to 256 B.
func TestDirectoryNoticeFitsItsBound(t *testing.T) {
	notice := &DirectoryNotice{
		RequestId:          testBytes(testIdSize),
		RequesterSidecarId: testBytes(testIdSize),
		EntrySeq:           math.MaxUint64,
		NotAfterMillis:     math.MaxInt64,
		State:              2,
		Outcome:            2,
	}
	for range testNoticeDecisions {
		notice.Decisions = append(notice.Decisions, &DecisionRef{
			DeciderSidecarId: testBytes(testIdSize),
			Seq:              math.MaxUint64,
			HeaderSha256:     testBytes(testHashSize),
		})
	}
	if size := testSize(t, notice); size > testNoticeBound {
		t.Errorf("a notice takes %d B, over %d", size, testNoticeBound)
	}
}
