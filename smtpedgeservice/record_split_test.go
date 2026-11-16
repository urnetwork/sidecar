// smtpRecordSplitter (SMTP-M9-13): whole records however the stream is cut, nothing dropped, a record past the
// bound or cut short refused; and the ServerHello's version read in the clear.

package smtpedgeservice_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// A reader handing out its bytes in the pieces cuts names, then the rest.
type cutReader struct {
	data []byte
	cuts []int
}

func (self *cutReader) Read(buffer []byte) (int, error) {
	if len(self.data) == 0 {
		return 0, io.EOF
	}
	size := len(self.data)
	if 0 < len(self.cuts) {
		size = self.cuts[0]
		self.cuts = self.cuts[1:]
	}
	size = min(size, len(buffer), len(self.data))
	n := copy(buffer, self.data[:size])
	self.data = self.data[n:]
	return n, nil
}

func testTlsRecord(contentType byte, body []byte) []byte {
	return append([]byte{contentType, 3, 3, byte(len(body) >> 8), byte(len(body))}, body...)
}

// Records cut at every octet of the stream, and one octet at a time, come out whole and in order.
func TestRecordsSplitAtEveryByteReassemble(t *testing.T) {
	records := [][]byte{
		testTlsRecord(22, bytes.Repeat([]byte{1}, 300)),
		testTlsRecord(20, []byte{1}),
		testTlsRecord(23, bytes.Repeat([]byte{2}, 17)),
		testTlsRecord(23, nil),
		testTlsRecord(23, bytes.Repeat([]byte{3}, 1024)),
	}
	stream := bytes.Join(records, nil)
	check := func(reader io.Reader) {
		t.Helper()
		got, err := smtpedgeservice.SplitRecordsForTest(reader, 5+16*1024+2048)
		if !errors.Is(err, io.EOF) || len(got) != len(records) {
			t.Fatalf("%d records, %v", len(got), err)
		}
		for i := range records {
			if !bytes.Equal(got[i], records[i]) {
				t.Fatalf("record %d differs", i)
			}
		}
	}
	for cut := 1; cut < len(stream); cut += 1 {
		check(&cutReader{data: stream, cuts: []int{cut}})
	}
	ones := make([]int, len(stream))
	for i := range ones {
		ones[i] = 1
	}
	check(&cutReader{data: stream, cuts: ones})
}

// A record past the bound is refused, not cut, and a stream ending inside a record is no clean end.
func TestRecordSplitterRefusesWhatItCannotRelayWhole(t *testing.T) {
	record := testTlsRecord(23, bytes.Repeat([]byte{4}, 100))
	if _, err := smtpedgeservice.SplitRecordsForTest(bytes.NewReader(record), 104); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("a record past the bound: %v", err)
	}
	if _, err := smtpedgeservice.SplitRecordsForTest(bytes.NewReader(record), 105); !errors.Is(err, io.EOF) {
		t.Fatalf("a record at the bound: %v", err)
	}
	for _, cut := range []int{3, 5, 50} {
		got, err := smtpedgeservice.SplitRecordsForTest(bytes.NewReader(record[:cut]), 1000)
		if len(got) != 0 || errors.Is(err, io.EOF) && cut != 0 || err == nil {
			t.Fatalf("cut at %d: %d records, %v", cut, len(got), err)
		}
	}
}

// The ServerHello's version: 1.3's supported_versions, else the legacy field, and 0 for anything else.
func TestServerHelloVersionIsReadInTheClear(t *testing.T) {
	serverHello := func(extensions []byte) []byte {
		body := []byte{3, 3}
		body = append(body, bytes.Repeat([]byte{9}, 32)...)
		body = append(body, 0)       // session id
		body = append(body, 0x13, 1) // suite
		body = append(body, 0)       // compression
		body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
		body = append(body, extensions...)
		message := append([]byte{2, 0, byte(len(body) >> 8), byte(len(body))}, body...)
		return testTlsRecord(22, message)
	}
	tls13 := serverHello([]byte{0, 43, 0, 2, 3, 4})
	if version := smtpedgeservice.ServerHelloVersionForTest(tls13); version != 0x0304 {
		t.Fatalf("1.3 read as %#x", version)
	}
	if version := smtpedgeservice.ServerHelloVersionForTest(serverHello([]byte{0xff, 1, 0, 1, 0})); version != 0x0303 {
		t.Fatalf("1.2 read as %#x", version)
	}
	for _, record := range [][]byte{testTlsRecord(23, []byte{2, 0, 0, 1}), testTlsRecord(22, []byte{1, 0}), tls13[:20]} {
		if version := smtpedgeservice.ServerHelloVersionForTest(record); version != 0 && version != 0x0303 {
			t.Fatalf("not a whole ServerHello read as %#x", version)
		}
	}
}
