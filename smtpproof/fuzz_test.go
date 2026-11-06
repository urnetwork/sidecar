// Hostile input for what the edge parses before any proof: a sidecar or an MX writes all of it, so a
// panic here would be a remote crash of smtpedge (§22.6). Each fuzz target's seeds also run as an
// ordinary test.

package smtpproof

import (
	"context"
	"math/rand"
	"testing"

	"github.com/urnetwork/sidecar"
)

func FuzzParseClientHello(f *testing.F) {
	f.Add([]byte{3, 3})
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, input []byte) {
		tlsParseClientHello(input)
	})
}

func FuzzParseServerHello(f *testing.F) {
	f.Add(testServerHelloBody(make([]byte, tlsRandomBytes), tlsSuiteAes128GcmSha256, []byte{0, 43, 0, 2, 3, 4}))
	f.Add(testServerHelloBody(tlsHelloRetryRandom, tlsSuiteAes128GcmSha256, []byte{0, 51, 0, 2, 0, 29}))
	f.Fuzz(func(t *testing.T, input []byte) {
		tlsParseServerHello(input)
	})
}

func FuzzParseCertificate(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 5, 0, 0, 2, 1, 2})
	f.Fuzz(func(t *testing.T, input []byte) {
		tlsParseCertificate(tlsVersion13, input)
		tlsParseCertificate(tlsVersion12, input)
	})
}

func FuzzParseServerKeyExchange(f *testing.F) {
	f.Add([]byte{3, 0, 29, 1, 9, 4, 3, 0, 1, 7})
	f.Fuzz(func(t *testing.T, input []byte) {
		tlsParseServerKeyExchange(input)
	})
}

func FuzzParseReplies(f *testing.F) {
	f.Add([]byte("250-mx\r\n250 CHUNKING\r\n"))
	f.Add([]byte("250\r\n"))
	f.Add([]byte("25"))
	f.Fuzz(func(t *testing.T, input []byte) {
		parseReplies(input)
		for count := 1; count < 4; count++ {
			splitReplies(input, count)
		}
	})
}

func FuzzCheckHeaderBlock(f *testing.F) {
	f.Add([]byte(testHeaderBlock()))
	f.Add([]byte("\r\n\r\n"))
	f.Add([]byte("From: <a@b>\r\n\r\n"))
	preamble := newSessionPreamble(testJob("", "bob").Preamble)
	f.Fuzz(func(t *testing.T, input []byte) {
		checkHeaderBlock(input, preamble)
		checkDataLines(input)
		dotStuffed(input)
	})
}

// A record of random length and octets, with framing that matches or does not.
func testRandomRecord(random *rand.Rand) []byte {
	payload := make([]byte, random.Intn(300))
	random.Read(payload)
	record := tlsFrameRecord([]uint8{tlsRecordChangeCipherSpec, tlsRecordAlert, tlsRecordHandshake, tlsRecordApplicationData, 0}[random.Intn(5)], tlsVersion12, payload)
	if random.Intn(8) == 0 {
		return record[:random.Intn(len(record)+1)]
	}
	return record
}

func TestTheGateSurvivesRandomRecordsInEveryPhase(t *testing.T) {
	// a fixed seed: the point is the same hostile sequence every run, at each point of a real handshake
	random := rand.New(rand.NewSource(1))
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		for stop := 0; stop <= len(fixture.trace); stop++ {
			for range 6 {
				gate := fixture.gate(&testFixedVerifier{})
				for _, entry := range fixture.trace[:stop] {
					switch {
					case entry.shts != nil:
						gate.DiscloseShts(entry.shts)
					case entry.fromClient:
						gate.ClientRecord(entry.record)
					default:
						gate.ServerRecord(entry.record)
					}
				}
				for range 20 {
					switch random.Intn(4) {
					case 0:
						gate.ClientRecord(testRandomRecord(random))
					case 1:
						gate.ServerRecord(testRandomRecord(random))
					case 2:
						gate.DiscloseShts(testRandomRecord(random))
					default:
						gate.VerifyPart(context.Background(), &sidecar.SmtpProofPart{
							Index:             uint32(random.Intn(6)),
							Mode:              uint32(random.Intn(4)),
							FirstRecord:       uint64(random.Intn(6)),
							LastRecord:        uint64(random.Intn(8)),
							Last:              random.Intn(2) == 0,
							ServerRecordCount: uint64(random.Intn(4)),
							Records:           [][]byte{testRandomRecord(random), testRandomRecord(random)},
						})
					}
				}
			}
		}
	}
}

func TestAHugeDeclaredRecipientCountCostsNothing(t *testing.T) {
	// the count is the sidecar's, and pi2's shape is checked against it before anything is built
	statement := &partStatement{
		session:       &sessionStatement{preamble: &sessionPreamble{recipientCount: 1<<32 - 1}},
		index:         2,
		mode:          partModeBdat,
		clientRecords: []*partRecord{{}, {}},
	}
	if _, err := partRoles(statement); err == nil {
		t.Error("two records fit a huge recipient count")
	}
}
