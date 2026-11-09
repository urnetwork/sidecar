//go:build !sidecar_http

// §16.11's caps where a reader meets them, on sidecartest's streams: an announce, request, decision or erasure request
// entry past its caps shows with no body, invalid, and alarms over_cap, its header and its writer's chain standing, so
// a version past its caps is never shown; and a secret in a run's title is signed as [REDACTED:<rule>], with the
// privacy harness's scan finding it in no capture. External, as record_reader_test.go, whose world these run in.

package sidecar_test

import (
	"bytes"
	"crypto/rand"
	mathrand "math/rand/v2"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Seals body, as stored, as the chain's next entry of kind: by hand, so a body no writer would seal reaches the stream.
func (self *testRecordHandChain) sealBody(kind sidecar.RecordKind, body []byte) *sidecar.RecordSealedEntry {
	self.device.t.Helper()
	sealed, err := sidecar.RecordSeal(self.env, &sidecar.RecordSealArgs{
		LogId:         self.device.world.vaultId,
		Kind:          kind,
		Source:        sidecar.RecordSourceObserved,
		TimeMillis:    self.device.world.clock.Now().UnixMilli(),
		PolicyVersion: self.device.world.auth.Tip().Pin().GetVersion(),
		StoredBody:    body,
	})
	if err != nil {
		self.device.t.Fatal(err)
	}
	return sealed
}

// A run item every check takes, renewed now.
func testDirectoryReaderRun(t *testing.T, world *testRecordWorld, device *testRecordDevice) *protocol.Announcement {
	t.Helper()
	renewedMillis := world.clock.Now().UnixMilli()
	expiresMillis, _ := sidecar.DirectoryAnnouncementExpiresMillis(sidecar.DirectoryAnnouncementKindRun, renewedMillis)
	return &protocol.Announcement{
		AnnouncementId: sidecar.NewId().Bytes(),
		Kind:           uint32(sidecar.DirectoryAnnouncementKindRun),
		Version:        1,
		StartedMillis:  renewedMillis,
		RenewedMillis:  renewedMillis,
		ExpiresMillis:  expiresMillis,
		State:          uint32(sidecar.DirectoryAnnouncementStateActive),
		Who: &protocol.AnnounceWho{
			MemberId:   world.memberId.Bytes(),
			SidecarId:  device.sidecarId.Bytes(),
			AgentId:    sidecar.NewId().Bytes(),
			AgentLabel: "builder",
			Harness:    "claude-code",
		},
		What:  &protocol.AnnounceWhat{Title: "Fix the deploy", RunId: sidecar.NewId().Bytes()},
		Where: &protocol.AnnounceWhere{Project: "git.example/team/billing", Branch: "fix/deploy"},
	}
}

// A member's own request for read on a repo.
func testDirectoryReaderRequest() *protocol.DirectoryRequest {
	return &protocol.DirectoryRequest{
		RequestId:       sidecar.NewId().Bytes(),
		Target:          &protocol.RequestTarget{RepoId: sidecar.NewId().Bytes()},
		Subject:         sidecar.NewId().Bytes(),
		SubjectIsMember: true,
		Role:            uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_READER),
		NotAfterMillis:  sidecar.DirectoryRequestDefaultExpiry.Milliseconds(),
		Reason:          "to review the billing migrations",
		FiledBy:         uint32(sidecar.DirectoryFiledByPerson),
	}
}

func testDirectoryReaderMarshal(t *testing.T, message proto.Message) []byte {
	t.Helper()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// §22.6 and §16.11's caps row: each directory entry past its caps shows with no body, invalid, and alarms over_cap,
// while its header stands and the next entry chains on it; entries within their caps show their bodies.
func TestDirectoryReaderIgnoresEntriesPastTheirCaps(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	hand := device.handChain()

	longTitle := testDirectoryReaderRun(t, world, device)
	longTitle.What.Title = strings.Repeat("t", sidecar.DirectoryRunTitleByteCount+1)
	longReason := testDirectoryReaderRequest()
	longReason.Reason = strings.Repeat("r", sidecar.DirectoryReasonByteCount+1)
	namedDenial := &protocol.DirectoryDecision{
		RequestId:          sidecar.NewId().Bytes(),
		RequestEntrySha256: bytes.Repeat([]byte{0x71}, 32),
		Outcome:            uint32(sidecar.DirectoryOutcomeDenied),
		Subject:            sidecar.NewId().Bytes(),
	}
	noMarker := &protocol.DirectoryErasureRequest{RequestId: sidecar.NewId().Bytes(), RepoId: sidecar.NewId().Bytes()}
	validRun := testDirectoryReaderMarshal(t, testDirectoryReaderRun(t, world, device))
	validRequest := testDirectoryReaderMarshal(t, testDirectoryReaderRequest())

	entries := []*sidecar.RecordSealedEntry{
		hand.sealBody(sidecar.RecordKindAnnounce, testDirectoryReaderMarshal(t, longTitle)),
		hand.sealBody(sidecar.RecordKindRequest, testDirectoryReaderMarshal(t, longReason)),
		hand.sealBody(sidecar.RecordKindDecision, testDirectoryReaderMarshal(t, namedDenial)),
		hand.sealBody(sidecar.RecordKindErasureRequest, testDirectoryReaderMarshal(t, noMarker)),
		hand.sealBody(sidecar.RecordKindAnnounce, validRun),
		hand.sealBody(sidecar.RecordKindRequest, validRequest),
	}
	device.pushHand([]uint64{1, 2, 3, 4, 5, 6}, entries, nil)
	reader := world.newReader(nil, nil)
	read := reader.sync(t, world)
	if len(read) != len(entries) {
		t.Fatalf("%d entries read of %d", len(read), len(entries))
	}
	for index, entry := range read[:4] {
		if !entry.BodyInvalid || entry.Body != nil || entry.State != sidecar.RecordEntryLive {
			t.Errorf("entry %d past its caps: invalid %t, a body of %d bytes, state %v", index, entry.BodyInvalid, len(entry.Body), entry.State)
		}
	}
	if read[4].BodyInvalid || !bytes.Equal(read[4].Body, validRun) || read[5].BodyInvalid || !bytes.Equal(read[5].Body, validRequest) {
		t.Error("an entry within its caps did not show its body")
	}
	want := slices.Repeat([]sidecar.SidecarRecordAlarm{sidecar.SidecarRecordAlarmOverCap}, 4)
	if reasons := reader.reasons(); !slices.Equal(reasons, want) {
		t.Errorf("alarms %v, want %v", reasons, want)
	}
}

// §16.11's redaction row and RECORD-M6-11's test: a secret in a run's title is signed as [REDACTED:<rule>], and the
// privacy harness's scan finds it in no capture: not in the entry a push carries, not in its deposit form, and not in
// the item a reader opens, which every admitted sidecar reads. The same scan finds it in the item before redaction.
func TestDirectoryRedactedTitleIsSignedWithNoSecretInAnyCapture(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	hand := device.handChain()

	// a synthetic token in the redactor's github-pat form, drawn from a fixed seed: no real secret
	random := mathrand.New(mathrand.NewPCG(7, 11))
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	token := make([]byte, 36)
	for index := range token {
		token[index] = alphabet[random.IntN(len(alphabet))]
	}
	secret := "ghp_" + string(token)

	item := testDirectoryReaderRun(t, world, device)
	item.What.Title = "redeploy with " + secret + " from the vault"
	unredacted := testDirectoryReaderMarshal(t, item)
	redactor, err := sidecar.NewRedactor(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	redactions, err := sidecar.DirectoryRedact(redactor, item)
	if err != nil {
		t.Fatal(err)
	}
	if len(redactions) != 1 || redactions[0].Field != "what.title" || redactions[0].Rule != "github-pat" {
		t.Fatalf("redactions %v", redactions)
	}
	body := testDirectoryReaderMarshal(t, item)
	if err := sidecar.RecordBodyValidateStored(sidecar.RecordKindAnnounce, body); err != nil {
		t.Fatalf("the redacted item, to its writer: %v", err)
	}
	sealed := hand.sealBody(sidecar.RecordKindAnnounce, body)
	device.pushHand([]uint64{1}, []*sidecar.RecordSealedEntry{sealed}, nil)
	read := world.newReader(nil, nil).sync(t, world)
	if len(read) != 1 || read[0].BodyInvalid {
		t.Fatalf("%d entries read", len(read))
	}
	opened, err := sidecar.DirectoryDecodeAnnouncement(read[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	if opened.GetWhat().GetTitle() != "[REDACTED:github-pat]" {
		t.Errorf("signed with the title %+q", opened.GetWhat().GetTitle())
	}

	capture := sidecartest.NewPrivacyCapture()
	capture.Forbid("the title's token", []byte(secret))
	slotId := sidecar.NewId()
	capture.Add(sidecartest.PrivacyClassObject, "the announce entry", sealed.EntryBytes(&slotId, 0))
	capture.Add(sidecartest.PrivacyClassObject, "the announce entry deposited", sealed.Deposit().GetEntry())
	capture.Add(sidecartest.PrivacyClassMcp, "the item as a reader opens it", read[0].Body)
	if findings := capture.Scan(); len(findings) != 0 {
		t.Fatalf("a capture holds the token: %v", findings)
	}
	capture.Add(sidecartest.PrivacyClassMcp, "the item before redaction", unredacted)
	if findings := capture.Scan(); len(findings) == 0 {
		t.Error("the scan missed the token in the item before redaction")
	}
}
