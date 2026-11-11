//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// §22.6 and SOCK-M5-15: the share's fixed-width get header is hostile input from any sidecar of the network. No input
// panics the decoder, which takes exactly 57 bytes of version 1 and re-encodes them byte for byte; and no input the
// decoder refuses changes a share's state, while one that decodes spends at most one use, and only with the secret.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A header for get_id at offset under secret, a getter's first bytes.
func testShareHeader(secret []byte, getId Id, offset uint64) []byte {
	return (&socketShareGet{secret: secret, getId: getId, offset: offset}).encode()
}

// A log in memory, enough for a share's decision.
type testShareMemoryLog struct {
	records [][]byte
}

func (self *testShareMemoryLog) Append(record []byte) error {
	self.records = append(self.records, append([]byte(nil), record...))
	return nil
}

func (self *testShareMemoryLog) Read(visit func(index uint64, record []byte) error) error {
	for index, record := range self.records {
		if err := visit(uint64(index), append([]byte(nil), record...)); err != nil {
			return err
		}
	}
	return nil
}

func FuzzShareHeader(f *testing.F) {
	secret := bytes.Repeat([]byte{0x77}, socketShareSecretByteCount)
	content := []byte("synthetic shared bytes")
	path := filepath.Join(f.TempDir(), "data.bin")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		f.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		f.Fatal(err)
	}
	sum := sha256.Sum256(content)
	record := &socketShareRecord{
		Token:        "abcdefghijklmnopqrstuvwxyz",
		Path:         path,
		Size:         info.Size(),
		MtimeNanos:   info.ModTime().UnixNano(),
		Sha256:       sum[:],
		Secret:       secret,
		Uses:         1,
		ExpireMillis: testSocketNow.Add(time.Hour).UnixMilli(),
	}
	getter := testSocketId("getter")
	valid := testShareHeader(secret, testSocketId("get"), 0)
	f.Add(valid)
	f.Add(testShareHeader(bytes.Repeat([]byte{0x01}, socketShareSecretByteCount), testSocketId("get"), 0))
	f.Add(testShareHeader(secret, testSocketId("get"), uint64(len(content))+1))
	f.Add(append([]byte{2}, valid[1:]...))
	f.Add(valid[:56])
	f.Add(append(append([]byte(nil), valid...), 0))
	f.Add(append(valid[:49], 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, header []byte) {
		get, decodeErr := decodeSocketShareGet(header)
		if decodeErr == nil {
			if len(header) != socketShareGetByteCount || header[0] != socketShareVersion || !bytes.Equal(get.encode(), header) {
				t.Fatal("an accepted header that does not re-encode to itself")
			}
		} else if len(header) == socketShareGetByteCount && header[0] == socketShareVersion && header[49] < 0x80 {
			t.Fatal("a well-formed header refused")
		}

		log := &testShareMemoryLog{}
		state := newSocketShareState()
		if err := appendSocketShareRow(log, state, record); err != nil {
			t.Fatal(err)
		}
		share := &socketShare{
			shares: &socketShares{clock: newTestSocketClock(), settings: DefaultSidecarSocketSettings().Share},
			token:  record.Token,
			log:    log,
			state:  state,
			conns:  map[*SocketConn]bool{},
		}
		decision := share.decide(header, getter)
		reserved := len(log.records) - 1
		if decodeErr != nil && (decision.kind != socketShareDecisionReset || reserved != 0 || len(state.reserves) != 0) {
			t.Fatalf("a refused header changed the share: decision %v, %d rows", decision.kind, reserved)
		}
		if 1 < reserved || (reserved == 1 && (decision.kind != socketShareDecisionOk || !bytes.Equal(get.secret, secret))) {
			t.Fatalf("%d reserves on decision %v", reserved, decision.kind)
		}
	})
}
