// The re-form record's encoding (gkm_reform.go; QD-1143): the time a sync last tried the finishing phase rides after
// the request, absent from a record no sync has tried, so a record kept before the field decodes as untried; any other
// tail, or a request length past the record's end, is refused as malformed.

package sidecar

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestGkmReformRecordKeepsTheTimeOfItsLastResume(t *testing.T) {
	record := &gkmReformRecord{
		phase:      gkmReformPhaseFinishing,
		groupId:    NewId(),
		generation: 7,
		request:    []byte("a synthetic reform request"),
	}
	untried := record.encode()
	decoded, err := decodeGkmReformRecord(untried)
	if err != nil || decoded.phase != record.phase || decoded.groupId != record.groupId || decoded.generation != 7 ||
		!bytes.Equal(decoded.request, record.request) || !decoded.resumedAt.IsZero() {
		t.Fatalf("an untried record: %+v, %v", decoded, err)
	}

	record.resumedAt = time.UnixMilli(1_790_000_000_123)
	tried := record.encode()
	if len(tried) != len(untried)+8 || !bytes.Equal(tried[:len(untried)], untried) {
		t.Fatalf("the try's time is not the tail of the untried record's bytes")
	}
	decoded, err = decodeGkmReformRecord(tried)
	if err != nil || !decoded.resumedAt.Equal(record.resumedAt) || !bytes.Equal(decoded.request, record.request) {
		t.Fatalf("a tried record: %+v, %v", decoded, err)
	}

	for _, malformed := range [][]byte{
		// a tail that is no time
		append(bytes.Clone(untried), 1, 2, 3),
		append(bytes.Clone(tried), 0),
		// a request length past the end
		untried[:len(untried)-1],
	} {
		if _, err := decodeGkmReformRecord(malformed); !errors.Is(err, ErrGkmMalformed) {
			t.Errorf("a malformed record of %d bytes: %v", len(malformed), err)
		}
	}
}
