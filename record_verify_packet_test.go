//go:build !js

// The offline verifier on the committed packet vector, testdata/record/packets/approval.json, with nothing but the
// file and the log key a recipient pins: RECORD.md section 20's packet case, "passes a good packet offline and fails
// on each altered byte class". Each class is one byte changed in the note, an inclusion path, a header, a salt, a
// body, a decision or its sshsig field, and each must fail the step that covers it. Not on the js leg, which reads no
// file.

package sidecar_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The vector's packet and the log key it verifies under.
func readTestPacketVector(t *testing.T) ([]byte, string) {
	t.Helper()
	content, err := os.ReadFile("testdata/record/packets/approval.json")
	if err != nil {
		t.Fatal(err)
	}
	vector := struct {
		LogKey string `json:"log_key"`
		Packet string `json:"packet"`
	}{}
	if err := json.Unmarshal(content, &vector); err != nil {
		t.Fatal(err)
	}
	packet, err := base64.StdEncoding.DecodeString(vector.Packet)
	if err != nil {
		t.Fatal(err)
	}
	return packet, vector.LogKey
}

func TestRecordVerifyPacketVectorPasses(t *testing.T) {
	packet, logKey := readTestPacketVector(t)
	report, err := sidecar.VerifyRecordDisclosurePacket(packet, &sidecar.RecordVerifyArgs{LogKeys: []string{logKey}})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Ok || len(report.Entries) != 4 || len(report.Checkpoints) != 1 {
		t.Fatalf("the vector: %+v", report)
	}
	for _, entry := range report.Entries {
		if !entry.Inclusion || !entry.Header || !entry.Body || !entry.Content || !entry.Approval {
			t.Errorf("a step did not pass for the %s entry: %+v", entry.Kind, entry)
		}
	}
}

func TestRecordVerifyPacketFailsOnEachAlteredByteClass(t *testing.T) {
	good, logKey := readTestPacketVector(t)
	// the entry of kind in packet
	entryOf := func(packet *protocol.DisclosurePacket, kind sidecar.RecordKind) *protocol.DisclosedEntry {
		for _, entry := range packet.GetEntries() {
			opened, err := sidecar.VerifyRecordOpening(&protocol.Opening{Header: entry.GetOpening().GetHeader()})
			if err == nil && opened.Header.Kind() == kind {
				return entry
			}
		}
		t.Fatalf("the vector has no %s entry", kind)
		return nil
	}
	// re-marshals a decision's Signed with its body changed, leaving the signature as it was
	alterDecision := func(entry *protocol.DisclosedEntry, change func(decision *protocol.ApprovalDecision)) {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(entry.GetOpening().GetBody(), signed); err != nil {
			t.Fatal(err)
		}
		decision := &protocol.ApprovalDecision{}
		if err := proto.Unmarshal(signed.GetBody(), decision); err != nil {
			t.Fatal(err)
		}
		change(decision)
		body, err := proto.Marshal(decision)
		if err != nil {
			t.Fatal(err)
		}
		signed.Body = body
		stored, err := proto.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		entry.Opening.Body = stored
	}
	cases := []struct {
		name   string
		change func(packet *protocol.DisclosurePacket)
		// the step that must fail, by what it leaves false
		failed func(report *sidecar.RecordVerifyReport) bool
	}{
		{name: "note", change: func(packet *protocol.DisclosurePacket) {
			// the size line: the note no longer verifies under the log key
			note := packet.Checkpoints[0]
			for i, b := range note {
				if b == '\n' {
					note[i+1] ^= 1
					break
				}
			}
		}, failed: func(report *sidecar.RecordVerifyReport) bool { return 0 < len(report.Checkpoints[0].Failures) }},
		{name: "path", change: func(packet *protocol.DisclosurePacket) {
			entry := entryOf(packet, sidecar.RecordKindApproval)
			if len(entry.InclusionPath) == 0 {
				t.Fatal("the vector's approval entry has no path")
			}
			entry.InclusionPath[0][0] ^= 1
		}, failed: func(report *sidecar.RecordVerifyReport) bool {
			return anyTestEntry(report, func(entry *sidecar.RecordVerifyEntry) bool { return !entry.Inclusion })
		}},
		{name: "leaf index", change: func(packet *protocol.DisclosurePacket) {
			entryOf(packet, sidecar.RecordKindApproval).LeafIndex ^= 1
		}, failed: func(report *sidecar.RecordVerifyReport) bool {
			return anyTestEntry(report, func(entry *sidecar.RecordVerifyEntry) bool { return !entry.Inclusion })
		}},
		{name: "header", change: func(packet *protocol.DisclosurePacket) {
			// the header's time: its signature and its leaf both change
			entry := entryOf(packet, sidecar.RecordKindApproval)
			signed := &bridge.Signed{}
			if err := proto.Unmarshal(entry.GetOpening().GetHeader(), signed); err != nil {
				t.Fatal(err)
			}
			header := &protocol.RecordHeader{}
			if err := proto.Unmarshal(signed.GetBody(), header); err != nil {
				t.Fatal(err)
			}
			header.TimeMillis += 1
			body, err := proto.Marshal(header)
			if err != nil {
				t.Fatal(err)
			}
			signed.Body = body
			stored, err := proto.Marshal(signed)
			if err != nil {
				t.Fatal(err)
			}
			entry.Opening.Header = stored
		}, failed: func(report *sidecar.RecordVerifyReport) bool {
			return anyTestEntry(report, func(entry *sidecar.RecordVerifyEntry) bool { return !entry.Header && !entry.Inclusion })
		}},
		{name: "salt", change: func(packet *protocol.DisclosurePacket) {
			entryOf(packet, sidecar.RecordKindApproval).Opening.Salt[0] ^= 1
		}, failed: func(report *sidecar.RecordVerifyReport) bool {
			return anyTestEntry(report, func(entry *sidecar.RecordVerifyEntry) bool { return !entry.Body })
		}},
		{name: "body", change: func(packet *protocol.DisclosurePacket) {
			body := entryOf(packet, sidecar.RecordKindApproval).Opening.Body
			body[len(body)-1] ^= 1
		}, failed: func(report *sidecar.RecordVerifyReport) bool {
			return anyTestEntry(report, func(entry *sidecar.RecordVerifyEntry) bool { return !entry.Body })
		}},
		{name: "decision", change: func(packet *protocol.DisclosurePacket) {
			alterDecision(entryOf(packet, sidecar.RecordKindApprovalDecision), func(decision *protocol.ApprovalDecision) { decision.Uses += 1 })
		}, failed: func(report *sidecar.RecordVerifyReport) bool {
			return anyTestEntry(report, func(entry *sidecar.RecordVerifyEntry) bool { return !entry.Approval && !entry.Body })
		}},
		{name: "sshsig", change: func(packet *protocol.DisclosurePacket) {
			alterDecision(entryOf(packet, sidecar.RecordKindApprovalDecision), func(decision *protocol.ApprovalDecision) { decision.Sshsig = []byte("a signature added later") })
		}, failed: func(report *sidecar.RecordVerifyReport) bool {
			return anyTestEntry(report, func(entry *sidecar.RecordVerifyEntry) bool { return !entry.Approval && !entry.Body })
		}},
		{name: "a stated key", change: func(packet *protocol.DisclosurePacket) {
			packet.Keys[0].PublicKey[0] ^= 1
		}, failed: func(report *sidecar.RecordVerifyReport) bool {
			return anyTestEntry(report, func(entry *sidecar.RecordVerifyEntry) bool { return !entry.Header })
		}},
		{name: "the packet's log", change: func(packet *protocol.DisclosurePacket) {
			packet.LogId[0] ^= 1
		}, failed: func(report *sidecar.RecordVerifyReport) bool { return 0 < len(report.Failures) }},
	}
	for _, c := range cases {
		packet := &protocol.DisclosurePacket{}
		if err := proto.Unmarshal(good, packet); err != nil {
			t.Fatal(err)
		}
		c.change(packet)
		altered, err := proto.Marshal(packet)
		if err != nil {
			t.Fatal(err)
		}
		report, err := sidecar.VerifyRecordDisclosurePacket(altered, &sidecar.RecordVerifyArgs{LogKeys: []string{logKey}})
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if report.Ok || !c.failed(report) {
			t.Errorf("%s: a packet with it changed: ok %t, %+v", c.name, report.Ok, report)
		}
	}
}

// Whether any entry of the report satisfies check.
func anyTestEntry(report *sidecar.RecordVerifyReport, check func(entry *sidecar.RecordVerifyEntry) bool) bool {
	for _, entry := range report.Entries {
		if check(entry) {
			return true
		}
	}
	return false
}
