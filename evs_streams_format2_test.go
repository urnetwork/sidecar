//go:build !ios_extension

// Format admission for a stream's stored push and sealed part records.

package sidecar

import (
	"bytes"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// Both record layouts can carry a format-2 purge tail beside a format-1 signed statement. A reader checks
// the envelope using its admitted format and verifies the original payload in either layout.
func TestEvsReadStreamsUsesAdmittedFormatForStoredRecords(t *testing.T) {
	signer := newEvsTestSigner("stream record format")
	purgeList, err := EncodeEvsPurgeList(&protocol.EvsPurgeList{Marked: true})
	if err != nil {
		t.Fatal(err)
	}
	tail := &EvsBatchRecordTail{PurgeList: purgeList}
	for _, parted := range []bool{false, true} {
		plan := evsTestPlan(t, signer, "stream record format", 1)
		plan.Changes[0].BaseEntryVersion, plan.Changes[0].EntryVersion = 1, nil
		if parted {
			plan.SealedMetadata = bytes.Repeat([]byte{0x5a}, 1536*1024)
		}
		built, _ := evsTestBuildAndCheck(t, signer, plan)
		signed := built.Statement
		var records [][]byte
		if !parted {
			body := EvsPushRecordBody(signed.Bytes, built.Payload)
			records = [][]byte{evsTestReseedRecord(protocol.EvsBatchRecordType_EVS_BATCH_PUSH, signed, body).encodeFormat2(tail)}
		} else {
			records = make([][]byte, len(built.Parts)+1)
			var places []*EvsSealPart
			for i, part := range built.Parts {
				checked, err := EvsCheckPart(signed, part)
				if err != nil {
					t.Fatal(err)
				}
				places = append(places, &EvsSealPart{Place: &protocol.EvsPlace{Minute: uint32(i + 1)}, ChangesRoot: checked.Root,
					FirstTokenPath: checked.FirstTokenPath(), Changeless: !checked.HoldsChanges()})
				body := EvsPartRecordBody(signed.Bytes, part, nil, plan.BaseVersion)
				records[i+1] = evsTestReseedRecord(protocol.EvsBatchRecordType_EVS_BATCH_PART, signed, body).encodeFormat2(tail)
			}
			records[0] = evsTestReseedRecord(protocol.EvsBatchRecordType_EVS_BATCH_SEAL, signed, EvsSealRecordBody(signed.Bytes, places)).encode()
		}
		client := &EvsClient{args: &EvsClientArgs{Store: newEvsTestStore(t)}, settings: DefaultEvsSettings()}
		group := &evsStreamGroup{objects: newEvsReadObjects(client)}
		t.Cleanup(group.objects.close)
		for i, record := range records {
			if err := group.objects.add(&protocol.EvsReadObject{Kind: protocol.EvsReadObjectKind_EVS_READ_OBJECT_BATCH_RECORD, Id: plan.PushId.Bytes(), Number: uint64(i), Body: record}); err != nil {
				t.Fatal(err)
			}
		}
		repo := client.Repo(plan.RepoId)
		verified := &EvsVerifiedStatement{Statement: signed, Version: plan.BaseVersion + 1}
		read := &evsReadResult{refId: plan.RefId, objects: group.objects}
		if _, err := repo.streamVersion(t.Context(), read, group, verified, nil); !errors.Is(err, ErrEvsEntryRefused) {
			t.Fatalf("format-1 reader accepted a format-2 record or returned a different refusal: %v", err)
		}
		client.EnableFormat2Reader()
		version, err := repo.streamVersion(t.Context(), read, group, verified, nil)
		if err != nil || !bytes.Equal(version.Payload.SealedMetadata, plan.SealedMetadata) {
			t.Fatalf("format-2 reader failed to recover the signed payload, multipart %t: %v", parted, err)
		}
	}
}
