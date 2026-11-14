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
	preamble := newSessionPreamble(testJob("", "bob").Preamble, DefaultProofSettings())
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

// Does what a real verifier does first with a statement: build its public wires. Nothing past that
// matters here, since a hostile record has already done its worst by then.
type testAssigningVerifier struct{}

func (self *testAssigningVerifier) verifyPart(ctx context.Context, statement *partStatement, proof []byte) error {
	_, err := partShapeFor(DefaultProofSettings(), statement)
	return err
}

func TestAnEmptyRecordFailsClosedInEveryPart(t *testing.T) {
	// a record of nothing but its tag, which in 1.3 lacks even its type octet: the verifier's path is
	// reachable before any key is, so a panic here would be a sidecar taking down an edge
	for _, leg := range testTlsLegs() {
		capture := testDataCapture(t, leg)
		for _, index := range []uint32{1, 2, 3} {
			statement, _ := capture.part(t, index)
			overhead := tlsAeadTagBytes
			if statement.session.version == tlsVersion12 {
				overhead += tlsExplicitNonceBytes
			}
			empty := tlsFrameRecord(tlsRecordApplicationData, tlsVersion12, make([]byte, overhead))
			for i := range statement.clientRecords {
				clone := testCloneStatement(statement)
				clone.clientRecords[i].raw = empty
				if _, err := partShapeFor(DefaultProofSettings(), clone); err == nil {
					t.Errorf("%s: part %d record %d: a shape took an empty record", leg.name, index, i)
				}
			}
		}
	}
}

func TestTheGateSurvivesMutatedParts(t *testing.T) {
	// each real part in turn, every part before it honest so that this one is what reaches the
	// verifier's path, with each record cut to a size around where a record stops holding its tag,
	// nonce and type octet, dropped, or swapped: refused or unfit, and never a panic
	for _, leg := range testTlsLegs() {
		settings := DefaultProverSettings()
		settings.ForceData = true
		// parts short of the last, since only the last has its octet count compared before it verifies
		settings.DataPartBytes = 12
		fixture := testGateCapture(t, leg, testMxDefaults(), settings, testJob("one line\r\nanother line\r\nand a third\r\n", "bob", "carol"))
		if len(fixture.parts) < 5 {
			t.Fatalf("%s: %d parts, too few to reach a later DATA part", leg.name, len(fixture.parts))
		}
		for target, original := range fixture.parts {
			var mutations []func(part *sidecar.SmtpProofPart)
			for i := range original.Records {
				for _, size := range []int{0, 1, 15, 16, 17, 23, 24, 25, 40} {
					mutations = append(mutations, func(part *sidecar.SmtpProofPart) {
						part.Records[i] = tlsFrameRecord(tlsRecordApplicationData, tlsVersion12, make([]byte, size))
					})
				}
				mutations = append(mutations, func(part *sidecar.SmtpProofPart) {
					part.Records = part.Records[:i]
				}, func(part *sidecar.SmtpProofPart) {
					part.Records[i] = part.Records[(i+1)%len(part.Records)]
				})
			}
			for _, mutation := range mutations {
				open := testOpen(t, fixture, &testAssigningVerifier{})
				for index, honest := range fixture.parts[:target+1] {
					for uint64(len(open.gate.serverRecords)) < honest.ServerRecordCount {
						if err := open.gate.ServerRecord(open.server[0]); err != nil {
							t.Fatal(err)
						}
						open.server = open.server[1:]
					}
					part := *honest
					if index == target {
						part.Records = testCloneByteSlices(honest.Records)
						mutation(&part)
						open.gate.VerifyPart(context.Background(), &part)
						break
					}
					if _, err := open.gate.VerifyPart(context.Background(), &part); err != nil {
						t.Fatalf("%s: honest part %d: %v", leg.name, honest.Index, err)
					}
				}
			}
		}
	}
}

func TestAHugeDeclaredRecipientCountCostsNothing(t *testing.T) {
	// the count is the sidecar's: the preamble's check refuses it past RecipientMaxCount, and roles,
	// which follow from positions, build nothing by it
	preamble := newSessionPreamble(testJob("", "bob").Preamble, DefaultProofSettings())
	preamble.recipientCount = 1<<32 - 1
	if err := checkSessionPreamble(preamble); err == nil {
		t.Error("a preamble of a huge recipient count passed")
	}
	statement := &partStatement{
		session:       &sessionStatement{version: tlsVersion13, preamble: preamble},
		index:         2,
		mode:          partModeBdat,
		clientRecords: []*partRecord{{seq: 1}, {seq: 1 << 31}},
	}
	roles, err := partRoles(statement)
	if err != nil || roles[0] != recordRoleMail || roles[1] != recordRoleRcpt {
		t.Errorf("roles %v, %v", roles, err)
	}
}
