// record_route.go's stream paths: RECORD.md section 20's vectors at each directory boundary, the counter read back
// from each path and from nothing else, and §16.8's name-table bound held by real sealed rows: a full leaf of 2,048
// entries within 256 KiB, and e/ at §11.7's 3,584 children within 448 KiB.

package sidecar

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// Section 20's stream path vectors, and each one's counter read back.
func TestRecordStreamPathVectors(t *testing.T) {
	vectors := []struct {
		n    uint64
		path string
	}{
		{n: 1, path: "e/0/0/1"},
		{n: 2047, path: "e/0/0/2047"},
		{n: 2048, path: "e/0/1/2048"},
		{n: 4194303, path: "e/0/2047/4194303"},
		{n: 4194304, path: "e/1/0/4194304"},
	}
	for _, vector := range vectors {
		path, err := RecordStreamPath(vector.n)
		if err != nil || path != vector.path {
			t.Errorf("n %d: %q, %v, want %q", vector.n, path, err, vector.path)
		}
		n, ok := RecordStreamPathCounter(vector.path)
		if !ok || n != vector.n {
			t.Errorf("%q read back as %d, %t", vector.path, n, ok)
		}
	}
	if _, err := RecordStreamPath(0); err == nil {
		t.Error("counter 0 made a path")
	}
}

// Only a path RecordStreamPath makes reads back as a counter.
func TestRecordStreamPathCounterRefusesOtherPaths(t *testing.T) {
	for _, path := range []string{"", "e/0/0/0", "e/0/1/1", "e/0/0/01", "e/0/0/1/", "d/0/0/1", "e/0/0", "e/0/0/x", "e//0/1"} {
		if n, ok := RecordStreamPathCounter(path); ok {
			t.Errorf("%q read back as %d", path, n)
		}
	}
}

// §16.8's storage row: a leaf directory's 2,048 rows, sealed as evs seals them, stay within 256 KiB, at the longest
// names a stream reaches, and e/ at §11.7's 3,584 children stays within its 448 KiB.
func TestRecordStreamNameTablesStayWithinTheirBounds(t *testing.T) {
	repoId := evsTestId("record stream")
	keys := evsTestKeys(t, repoId, 1)
	table := func(names [][]byte) *protocol.EvsNameTable {
		parent, err := EvsPathToken(keys.path, EvsRootToken, []byte("e"))
		if err != nil {
			t.Fatal(err)
		}
		table := &protocol.EvsNameTable{}
		for _, name := range names {
			child, err := EvsPathToken(keys.path, parent, name)
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := EvsNameSeal(keys.manifest, parent, child, name)
			if err != nil {
				t.Fatal(err)
			}
			table.Names = append(table.Names, &protocol.EvsName{Token: child[:], Kind: 1, SealedName: sealed})
		}
		return table
	}
	// the last leaf of the 15 billionth-odd entry: the longest names any leaf holds
	leafNames := [][]byte{}
	last := uint64(3584*recordStreamLevelEntryCount - 1)
	for n := last - recordStreamLeafEntryCount + 1; n <= last; n += 1 {
		leafNames = append(leafNames, []byte(strconv.FormatUint(n, 10)))
	}
	if byteCount := EvsNameTableBoundByteCount(table(leafNames)); 256*1024 < byteCount {
		t.Errorf("a full leaf's table is %d bytes", byteCount)
	}
	topNames := [][]byte{}
	for n := 0; n < 3584; n += 1 {
		topNames = append(topNames, []byte(strconv.Itoa(n)))
	}
	if byteCount := EvsNameTableBoundByteCount(table(topNames)); EvsNameTableMaxBoundByteCount < byteCount {
		t.Errorf("e/ at 3,584 children is %d bytes", byteCount)
	}
	// and the path of that last entry parses back
	path, err := RecordStreamPath(last)
	if err != nil || !bytes.HasPrefix([]byte(path), []byte("e/3583/2047/")) {
		t.Errorf("the last entry's path is %q, %v", path, err)
	}
}
