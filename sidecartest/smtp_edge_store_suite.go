// The conformance suite for smtpedgeservice.SmtpEdgeStore (§14.9; SMTP-M5-01): what store.go
// promises, run on FakeSmtpEdgeStore here and on server's model store (SMTP-M5-06, SMTP-M9-18), so the
// fake stays honest (D-TEST-2). Every case runs through the interface alone, on ids and times of its
// own, so one store serves the whole run and a shared database's other rows change no verdict.
//
// A case is a plain function returning its first failure, and RunSmtpEdgeStoreSuite loops over them,
// as blobsuite does, since one store's cases are homogeneous variations (connect/CODESTYLE.md:216). A
// failure in one does not stop the next.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// How long one case may wait on a store before it fails. Real time, so only ever a failure's bound
// (§22.8): nothing here sleeps.
const smtpSuiteCaseTimeout = 30 * time.Second

// A start long past and one far ahead, so a halt's verdict holds on any store's clock in between.
var (
	smtpSuiteLongAgo  = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
	smtpSuiteFarAhead = time.Date(2099, time.December, 31, 0, 0, 0, 0, time.UTC)
)

type smtpSuiteCase struct {
	name string
	run  func(ctx context.Context, store smtpedgeservice.SmtpEdgeStore) error
}

// Runs every case on store. t is a testing.TB, as the other store suites take, so server's test env,
// which hands each attempt one, runs it on Postgres.
func RunSmtpEdgeStoreSuite(t testing.TB, store smtpedgeservice.SmtpEdgeStore) {
	t.Helper()
	for _, suiteCase := range smtpSuiteCases() {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), smtpSuiteCaseTimeout)
			defer cancel()
			if err := suiteCase.run(ctx, store); err != nil {
				t.Errorf("%s: %v", suiteCase.name, err)
			}
		}()
	}
}

func smtpSuiteCases() []smtpSuiteCase {
	return []smtpSuiteCase{
		{name: "an aggregate inserts once per reporter and report id", run: caseSmtpAggregateOnce},
		{name: "a report id from another reporter is another aggregate", run: caseSmtpAggregateOtherReporter},
		{name: "a repeated aggregate with other counts changes nothing and says so", run: caseSmtpAggregateRepeatOtherCounts},
		{name: "active halts drop expired rows", run: caseSmtpHaltsDropExpired},
		{name: "a halt set again under its id replaces it", run: caseSmtpHaltReplaced},
		{name: "sends are found by send id", run: caseSmtpFindBySendId},
		{name: "sends are found by message id hash", run: caseSmtpFindByMessageIdHash},
		{name: "sends are found by network within a time range", run: caseSmtpFindByNetwork},
		{name: "sends are found by sending address within a time range", run: caseSmtpFindBySendingAddress},
		{name: "a key of a time range alone is refused", run: caseSmtpFindRefusesTimeOnly},
		{name: "a batch inserted twice stores each send once", run: caseSmtpSendBatchIdempotent},
		{name: "one send id on another day is another send", run: caseSmtpSendIdPerDay},
		{name: "complaints insert, with or without a sealed copy", run: caseSmtpComplaintInserts},
	}
}

// Random octets, for send ids and report ids no other run shares.
func smtpSuiteRandom(byteCount int) []byte {
	value := make([]byte, byteCount)
	if _, err := rand.Read(value); err != nil {
		panic(err)
	}
	return value
}

// A time in 2031 or 2032, at a minute no other case is likely to pick, so a time range isolates a case
// on a shared store.
func smtpSuiteBase() time.Time {
	minutes := binary.BigEndian.Uint32(smtpSuiteRandom(4)) % (2 * 365 * 24 * 60)
	return time.Date(2031, time.January, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(minutes) * time.Minute)
}

// A send of network at start, from 192.0.2.10.
func smtpSuiteSend(networkId sidecar.Id, start time.Time) *smtpedgeservice.SmtpSendRecord {
	return &smtpedgeservice.SmtpSendRecord{
		SendId:           smtpSuiteRandom(12),
		NetworkId:        networkId,
		ClientId:         sidecar.NewId(),
		SendingAddress:   netip.MustParseAddr("192.0.2.10"),
		RecipientDomain:  "recipient.example",
		MxHost:           "mx.recipient.example",
		StartTime:        start,
		EndTime:          start.Add(time.Minute),
		ByteCount:        4096,
		MessageIdHash:    smtpedgeservice.SmtpMessageIdHash(fmt.Sprintf("<%x@net.root.example>", smtpSuiteRandom(8))),
		XUrRefKeyId:      1,
		RecipientCount:   3,
		MessageByteCount: 2048,
		TlsVersion:       0x0304,
		TlsLevel:         smtpedgeservice.SmtpTlsLevelDane,
		Result:           "sent",
	}
}

// One report of one count.
func smtpSuiteAggregate(reporter string, reportId string, networkId sidecar.Id, messageCount uint64) *smtpedgeservice.SmtpAggregateReport {
	return &smtpedgeservice.SmtpAggregateReport{
		Reporter:    reporter,
		ReportId:    reportId,
		Kind:        smtpedgeservice.SmtpAggregateKindDmarc,
		Day:         time.Date(2031, time.March, 1, 0, 0, 0, 0, time.UTC),
		ArrivalTime: time.Date(2031, time.March, 2, 3, 4, 5, 0, time.UTC),
		Counts: []*smtpedgeservice.SmtpAggregateCount{{
			NetworkId:     networkId,
			Domain:        "net.root.example",
			MessageCount:  messageCount,
			DkimPassCount: messageCount,
		}},
	}
}

// The send ids of sends, in order.
func smtpSuiteSendIds(sends []*smtpedgeservice.SmtpSendRecord) [][]byte {
	ids := [][]byte{}
	for _, send := range sends {
		ids = append(ids, send.SendId)
	}
	return ids
}

// Whether two lists of send ids are equal, in order.
func smtpSuiteSameIds(a [][]byte, b [][]byte) bool {
	return slices.EqualFunc(a, b, func(x []byte, y []byte) bool { return bytes.Equal(x, y) })
}

// Only the sends of networkIds, so another case's or run's rows on a shared store change no verdict.
func smtpSuiteOwnSends(sends []*smtpedgeservice.SmtpSendRecord, networkIds ...sidecar.Id) []*smtpedgeservice.SmtpSendRecord {
	own := []*smtpedgeservice.SmtpSendRecord{}
	for _, send := range sends {
		if slices.Contains(networkIds, send.NetworkId) {
			own = append(own, send)
		}
	}
	return own
}

func caseSmtpAggregateOnce(ctx context.Context, store smtpedgeservice.SmtpEdgeStore) error {
	reportId := fmt.Sprintf("report-%x", smtpSuiteRandom(8))
	report := smtpSuiteAggregate("reporter.example", reportId, sidecar.NewId(), 5)
	inserted, err := store.InsertAggregate(ctx, report)
	if err != nil {
		return err
	}
	if !inserted {
		return errors.New("a new report was not inserted")
	}
	inserted, err = store.InsertAggregate(ctx, report)
	if err != nil {
		return err
	}
	if inserted {
		return errors.New("the same report inserted twice")
	}
	return nil
}

func caseSmtpAggregateOtherReporter(ctx context.Context, store smtpedgeservice.SmtpEdgeStore) error {
	reportId := fmt.Sprintf("report-%x", smtpSuiteRandom(8))
	networkId := sidecar.NewId()
	for _, reporter := range []string{"first.example", "second.example"} {
		inserted, err := store.InsertAggregate(ctx, smtpSuiteAggregate(reporter, reportId, networkId, 1))
		if err != nil {
			return err
		}
		if !inserted {
			return fmt.Errorf("%s's report was not inserted", reporter)
		}
	}
	return nil
}

func caseSmtpAggregateRepeatOtherCounts(ctx context.Context, store smtpedgeservice.SmtpEdgeStore) error {
	reportId := fmt.Sprintf("report-%x", smtpSuiteRandom(8))
	networkId := sidecar.NewId()
	if _, err := store.InsertAggregate(ctx, smtpSuiteAggregate("reporter.example", reportId, networkId, 5)); err != nil {
		return err
	}
	// a second network's counts under the same pair, as a replay with altered rows would carry
	inserted, err := store.InsertAggregate(ctx, smtpSuiteAggregate("reporter.example", reportId, sidecar.NewId(), 500))
	if err != nil {
		return err
	}
	if inserted {
		return errors.New("a replay under a stored reporter and report id inserted")
	}
	return nil
}

func caseSmtpHaltsDropExpired(ctx context.Context, store smtpedgeservice.SmtpEdgeStore) error {
	networkId := sidecar.NewId()
	expired := &smtpedgeservice.SmtpHalt{HaltId: sidecar.NewId(), NetworkId: networkId, Trigger: smtpedgeservice.SmtpHaltTriggerCommunityComplaint, StartTime: smtpSuiteLongAgo}
	active := &smtpedgeservice.SmtpHalt{HaltId: sidecar.NewId(), NetworkId: networkId, Label: "quiet-otter", Trigger: smtpedgeservice.SmtpHaltTriggerLabelComplaint, StartTime: smtpSuiteFarAhead}
	for _, halt := range []*smtpedgeservice.SmtpHalt{expired, active} {
		if err := store.SetHalt(ctx, halt); err != nil {
			return err
		}
	}
	halts, err := store.ActiveHalts(ctx)
	if err != nil {
		return err
	}
	foundActive := false
	for _, halt := range halts {
		switch halt.HaltId {
		case expired.HaltId:
			return errors.New("an expired halt is active")
		case active.HaltId:
			foundActive = true
			if halt.NetworkId != networkId || halt.Label != "quiet-otter" || halt.Trigger != smtpedgeservice.SmtpHaltTriggerLabelComplaint || !halt.StartTime.Equal(smtpSuiteFarAhead) {
				return errors.New("an active halt does not read back as written")
			}
		}
	}
	if !foundActive {
		return errors.New("an active halt is missing")
	}
	return nil
}

func caseSmtpHaltReplaced(ctx context.Context, store smtpedgeservice.SmtpEdgeStore) error {
	halt := &smtpedgeservice.SmtpHalt{HaltId: sidecar.NewId(), NetworkId: sidecar.NewId(), Trigger: smtpedgeservice.SmtpHaltTriggerRecordCuts, StartTime: smtpSuiteFarAhead}
	if err := store.SetHalt(ctx, halt); err != nil {
		return err
	}
	replaced := *halt
	replaced.StartTime = smtpSuiteLongAgo
	if err := store.SetHalt(ctx, &replaced); err != nil {
		return err
	}
	halts, err := store.ActiveHalts(ctx)
	if err != nil {
		return err
	}
	for _, active := range halts {
		if active.HaltId == halt.HaltId {
			return errors.New("the replaced halt still holds")
		}
	}
	return nil
}

func caseSmtpFindBySendId(ctx context.Context, store smtpedgeservice.SmtpEdgeStore) error {
	networkId := sidecar.NewId()
	base := smtpSuiteBase()
	sends := []*smtpedgeservice.SmtpSendRecord{smtpSuiteSend(networkId, base), smtpSuiteSend(networkId, base.Add(time.Minute))}
	if err := store.InsertSends(ctx, sends); err != nil {
		return err
	}
	found, err := store.FindSends(ctx, &smtpedgeservice.SmtpJoinKey{SendId: sends[1].SendId})
	if err != nil {
		return err
	}
	if len(found) != 1 || !bytes.Equal(found[0].SendId, sends[1].SendId) {
		return fmt.Errorf("found %d sends by send id", len(found))
	}
	got := found[0]
	want := sends[1]
	if got.NetworkId != want.NetworkId || got.ClientId != want.ClientId || got.SendingAddress != want.SendingAddress ||
		got.RecipientDomain != want.RecipientDomain || got.MxHost != want.MxHost || !got.StartTime.Equal(want.StartTime) ||
		!got.EndTime.Equal(want.EndTime) || got.ByteCount != want.ByteCount || !bytes.Equal(got.MessageIdHash, want.MessageIdHash) ||
		got.XUrRefKeyId != want.XUrRefKeyId || got.RecipientCount != want.RecipientCount || got.MessageByteCount != want.MessageByteCount ||
		got.TlsVersion != want.TlsVersion || got.TlsLevel != want.TlsLevel || got.Result != want.Result || len(got.RetryOfSendId) != 0 {
		return errors.New("a send does not read back as written")
	}
	return nil
}

func caseSmtpFindByMessageIdHash(ctx context.Context, store smtpedgeservice.SmtpEdgeStore) error {
	networkId := sidecar.NewId()
	base := smtpSuiteBase()
	first := smtpSuiteSend(networkId, base)
	retry := smtpSuiteSend(networkId, base.Add(time.Hour))
	retry.MessageIdHash = first.MessageIdHash
	retry.RetryOfSendId = first.SendId
	other := smtpSuiteSend(networkId, base.Add(2*time.Hour))
	if err := store.InsertSends(ctx, []*smtpedgeservice.SmtpSendRecord{other, retry, first}); err != nil {
		return err
	}
	found, err := store.FindSends(ctx, &smtpedgeservice.SmtpJoinKey{MessageIdHash: first.MessageIdHash})
	if err != nil {
		return err
	}
	if !smtpSuiteSameIds(smtpSuiteSendIds(found), [][]byte{first.SendId, retry.SendId}) {
		return errors.New("a message id hash found the wrong sends, or out of order")
	}
	if !bytes.Equal(found[1].RetryOfSendId, first.SendId) {
		return errors.New("retry-of does not read back")
	}
	return nil
}

func caseSmtpFindByNetwork(ctx context.Context, store smtpedgeservice.SmtpEdgeStore) error {
	networkId := sidecar.NewId()
	otherNetworkId := sidecar.NewId()
	base := smtpSuiteBase()
	before := smtpSuiteSend(networkId, base.Add(-time.Hour))
	inside := smtpSuiteSend(networkId, base)
	after := smtpSuiteSend(networkId, base.Add(time.Hour))
	other := smtpSuiteSend(otherNetworkId, base)
	if err := store.InsertSends(ctx, []*smtpedgeservice.SmtpSendRecord{before, inside, after, other}); err != nil {
		return err
	}
	found, err := store.FindSends(ctx, &smtpedgeservice.SmtpJoinKey{NetworkId: networkId, Since: base.Add(-10 * time.Minute), Until: base.Add(10 * time.Minute)})
	if err != nil {
		return err
	}
	if !smtpSuiteSameIds(smtpSuiteSendIds(found), [][]byte{inside.SendId}) {
		return fmt.Errorf("a network's window found %d sends", len(found))
	}
	found, err = store.FindSends(ctx, &smtpedgeservice.SmtpJoinKey{NetworkId: networkId})
	if err != nil {
		return err
	}
	if !smtpSuiteSameIds(smtpSuiteSendIds(found), [][]byte{before.SendId, inside.SendId, after.SendId}) {
		return fmt.Errorf("a network with no window found %d sends", len(found))
	}
	return nil
}

func caseSmtpFindBySendingAddress(ctx context.Context, store smtpedgeservice.SmtpEdgeStore) error {
	networkId := sidecar.NewId()
	base := smtpSuiteBase()
	inside := smtpSuiteSend(networkId, base)
	edge := smtpSuiteSend(networkId, base.Add(10*time.Minute))
	outside := smtpSuiteSend(networkId, base.Add(11*time.Minute))
	otherAddress := smtpSuiteSend(networkId, base)
	otherAddress.SendingAddress = netip.MustParseAddr("192.0.2.11")
	if err := store.InsertSends(ctx, []*smtpedgeservice.SmtpSendRecord{inside, edge, outside, otherAddress}); err != nil {
		return err
	}
	found, err := store.FindSends(ctx, &smtpedgeservice.SmtpJoinKey{SendingAddress: netip.MustParseAddr("192.0.2.10"), Since: base.Add(-10 * time.Minute), Until: base.Add(10 * time.Minute)})
	if err != nil {
		return err
	}
	if !smtpSuiteSameIds(smtpSuiteSendIds(smtpSuiteOwnSends(found, networkId)), [][]byte{inside.SendId, edge.SendId}) {
		return errors.New("an address's window found the wrong sends")
	}
	return nil
}

func caseSmtpFindRefusesTimeOnly(ctx context.Context, store smtpedgeservice.SmtpEdgeStore) error {
	base := smtpSuiteBase()
	if _, err := store.FindSends(ctx, &smtpedgeservice.SmtpJoinKey{Since: base, Until: base.Add(time.Hour)}); !errors.Is(err, smtpedgeservice.ErrSmtpJoinKeyEmpty) {
		return fmt.Errorf("a time-only key answered %v", err)
	}
	if _, err := store.FindSends(ctx, &smtpedgeservice.SmtpJoinKey{}); !errors.Is(err, smtpedgeservice.ErrSmtpJoinKeyEmpty) {
		return fmt.Errorf("an empty key answered %v", err)
	}
	return nil
}

func caseSmtpSendBatchIdempotent(ctx context.Context, store smtpedgeservice.SmtpEdgeStore) error {
	networkId := sidecar.NewId()
	base := smtpSuiteBase()
	batch := []*smtpedgeservice.SmtpSendRecord{smtpSuiteSend(networkId, base), smtpSuiteSend(networkId, base.Add(time.Second))}
	for range 2 {
		if err := store.InsertSends(ctx, batch); err != nil {
			return err
		}
	}
	found, err := store.FindSends(ctx, &smtpedgeservice.SmtpJoinKey{NetworkId: networkId})
	if err != nil {
		return err
	}
	if !smtpSuiteSameIds(smtpSuiteSendIds(found), smtpSuiteSendIds(batch)) {
		return fmt.Errorf("a batch inserted twice left %d sends", len(found))
	}
	return nil
}

func caseSmtpSendIdPerDay(ctx context.Context, store smtpedgeservice.SmtpEdgeStore) error {
	networkId := sidecar.NewId()
	base := smtpSuiteBase()
	first := smtpSuiteSend(networkId, base)
	nextDay := smtpSuiteSend(networkId, base.Add(24*time.Hour))
	nextDay.SendId = first.SendId
	if err := store.InsertSends(ctx, []*smtpedgeservice.SmtpSendRecord{first, nextDay}); err != nil {
		return err
	}
	found, err := store.FindSends(ctx, &smtpedgeservice.SmtpJoinKey{SendId: first.SendId, NetworkId: networkId})
	if err != nil {
		return err
	}
	if len(found) != 2 {
		return fmt.Errorf("one send id on two days left %d sends", len(found))
	}
	return nil
}

func caseSmtpComplaintInserts(ctx context.Context, store smtpedgeservice.SmtpEdgeStore) error {
	complaint := &smtpedgeservice.SmtpComplaint{
		ComplaintId:   sidecar.NewId(),
		NetworkId:     sidecar.NewId(),
		Reporter:      "loop.example",
		Type:          smtpedgeservice.SmtpComplaintTypeAbuse,
		ArrivalTime:   smtpSuiteBase(),
		Domain:        "net.root.example",
		DkimDomain:    "net.root.example",
		DkimSelector:  "abcdefghijklmnopqrstuvwxyz",
		DkimResult:    "pass",
		MessageIdHash: smtpedgeservice.SmtpMessageIdHash("<id@net.root.example>"),
		JoinResult:    "high",
		SealedReport:  smtpSuiteRandom(64),
	}
	if err := store.InsertComplaint(ctx, complaint); err != nil {
		return err
	}
	unsealed := *complaint
	unsealed.ComplaintId = sidecar.NewId()
	unsealed.SealedReport = nil
	return store.InsertComplaint(ctx, &unsealed)
}
