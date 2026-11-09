// The conformance suite for certsservice.CertsStore (§13.8; TLS-M5-14): what store.go promises, run on
// FakeCertsStore here and on server's model.NewCertsStore (TLS-M5-16), so the fake stays honest
// (D-TEST-2). Every case writes rows of networks, sidecars, sets and serials of its own, and its times sit
// in a range of its own, so one store serves the whole run and a shared database's other rows change no
// verdict: a case that reads a whole queue or a whole CA's orders keeps only its own rows.
//
// Times are whole microseconds, as Postgres keeps them, and a row's order time is its cert_id's
// (CertsIdAt), as certs mints them.
//
// A case is a plain function returning its first failure, and RunCertsStoreSuite loops over them, as
// blobsuite does (connect/CODESTYLE.md:216). A failure in one does not stop the next.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
)

// How long one case may wait on a store before it fails. Real time, so only ever a failure's bound
// (§22.8): nothing here sleeps.
const certsSuiteCaseTimeout = 30 * time.Second

// What a store's own test does that the interface cannot.
type CertsStoreSuiteHooks struct {
	// Marks clientId as an ephemeral sidecar's, as network_client_owner.ephemeral does. nil skips the
	// case that needs it, and says so.
	MarkEphemeral func(ctx context.Context, clientId sidecar.Id) error
}

type certsSuiteCase struct {
	name string
	run  func(ctx context.Context, store certsservice.CertsStore, hooks *CertsStoreSuiteHooks) error
}

// Runs every case on store.
func RunCertsStoreSuite(t testing.TB, store certsservice.CertsStore, hooks *CertsStoreSuiteHooks) {
	t.Helper()
	if hooks == nil {
		hooks = &CertsStoreSuiteHooks{}
	}
	for _, suiteCase := range certsSuiteCases() {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), certsSuiteCaseTimeout)
			defer cancel()
			if err := suiteCase.run(ctx, store, hooks); err != nil {
				t.Errorf("%s: %v", suiteCase.name, err)
			}
		}()
	}
	if hooks.MarkEphemeral == nil {
		t.Log("no MarkEphemeral hook: an ephemeral client's flag was not read back")
	}
}

func certsSuiteCases() []certsSuiteCase {
	return []certsSuiteCase{
		{name: "a row reads back field for field", run: caseCertsRoundTrip},
		{name: "a second row under one id is a conflict", run: caseCertsInsertConflict},
		{name: "an unknown row is not found", run: caseCertsNotFound},
		{name: "a network lists only its rows, oldest first", run: caseCertsNetworkRows},
		{name: "an open order is found until it issues", run: caseCertsOpenOrder},
		{name: "a live certificate is found by its serial within its validity", run: caseCertsLiveBySerial},
		{name: "a transition applies only from its states, once", run: caseCertsTransition},
		{name: "a successor links once, and its predecessor is found", run: caseCertsSuccessor},
		{name: "a set counts as issued only from an older row with a serial", run: caseCertsSetIssuedBefore},
		{name: "a set's orders are those at the CA since a time", run: caseCertsSetOrders},
		{name: "new-set orders are the first certificates of their sets", run: caseCertsNewSetOrders},
		{name: "the queue reads queued rows after its cursor, oldest first", run: caseCertsQueue},
		{name: "a purge takes what ended before its time, and only that", run: caseCertsPurge},
		{name: "an ephemeral client reads as one", run: caseCertsEphemeral},
	}
}

// Random octets.
func certsSuiteRandom(byteCount int) []byte {
	value := make([]byte, byteCount)
	if _, err := rand.Read(value); err != nil {
		panic(err)
	}
	return value
}

// A start in a year of the case's own, to the microsecond, so cases share no time range.
func certsSuiteBase() time.Time {
	year := 2100 + int(certsSuiteRandom(1)[0])%800
	return time.Date(year, time.March, 1, 12, 0, 0, 0, time.UTC).Add(time.Duration(certsSuiteRandom(1)[0]) * time.Hour)
}

// A queued row of networkId's sidecar at orderTime, with a set and key of its own.
func certsSuiteRow(networkId sidecar.Id, orderTime time.Time) *sidecar.TlsCertRecord {
	return &sidecar.TlsCertRecord{
		CertId:              CertsIdAt(orderTime),
		NetworkId:           networkId,
		ClientId:            sidecar.NewId(),
		SidecarId:           sidecar.NewId(),
		IdentifierSetSha256: certsSuiteRandom(32),
		SpkiSha256:          certsSuiteRandom(32),
		Attestation:         certsSuiteRandom(96),
		Csr:                 certsSuiteRandom(200),
		State:               sidecar.TlsCertStateQueued,
	}
}

// The same set's next order, by the same sidecar under a new key.
func certsSuiteNextOrder(row *sidecar.TlsCertRecord, orderTime time.Time) *sidecar.TlsCertRecord {
	next := certsSuiteRow(row.NetworkId, orderTime)
	next.ClientId = row.ClientId
	next.SidecarId = row.SidecarId
	next.IdentifierSetSha256 = bytes.Clone(row.IdentifierSetSha256)
	return next
}

// Moves row to issued at ca with serial and a validity from notBefore, as an order's end does.
func certsSuiteIssue(ctx context.Context, store certsservice.CertsStore, row *sidecar.TlsCertRecord, ca certsservice.CertsCa, serial string, notBefore time.Time) error {
	for _, step := range []*certsservice.CertsTransition{
		{CertId: row.CertId, From: []sidecar.TlsCertState{sidecar.TlsCertStateQueued}, To: sidecar.TlsCertStateOrdering, Ca: ca, Profile: "tlsserver"},
		{
			CertId:     row.CertId,
			From:       []sidecar.TlsCertState{sidecar.TlsCertStateOrdering, sidecar.TlsCertStateWaitingDns},
			To:         sidecar.TlsCertStateIssued,
			AccountUri: "https://ca.example/acct/1",
			Serial:     serial,
			NotBefore:  notBefore,
			NotAfter:   notBefore.Add(45 * 24 * time.Hour),
		},
	} {
		applied, err := store.TransitionCert(ctx, step)
		if err != nil {
			return err
		}
		if !applied {
			return fmt.Errorf("the transition to %s did not apply", step.To)
		}
	}
	return nil
}

// The ids of rows, in order.
func certsSuiteIds(rows []*sidecar.TlsCertRecord) []sidecar.Id {
	ids := []sidecar.Id{}
	for _, row := range rows {
		ids = append(ids, row.CertId)
	}
	return ids
}

// The rows among got whose ids want names, in got's order.
func certsSuiteOwn(got []*sidecar.TlsCertRecord, want ...*sidecar.TlsCertRecord) []sidecar.Id {
	wantIds := certsSuiteIds(want)
	own := []sidecar.Id{}
	for _, row := range got {
		if slices.Contains(wantIds, row.CertId) {
			own = append(own, row.CertId)
		}
	}
	return own
}

// Whether two rows hold the same fields, times compared as instants.
func certsSuiteSameRow(got *sidecar.TlsCertRecord, want *sidecar.TlsCertRecord) error {
	equalTime := func(a time.Time, b time.Time) bool { return a.Equal(b) }
	chainsEqual := len(got.Chain) == len(want.Chain)
	for index := 0; chainsEqual && index < len(got.Chain); index += 1 {
		chainsEqual = bytes.Equal(got.Chain[index], want.Chain[index])
	}
	if got.CertId != want.CertId || got.NetworkId != want.NetworkId || got.ClientId != want.ClientId || got.SidecarId != want.SidecarId ||
		!bytes.Equal(got.IdentifierSetSha256, want.IdentifierSetSha256) || !bytes.Equal(got.SpkiSha256, want.SpkiSha256) ||
		!bytes.Equal(got.Attestation, want.Attestation) || !bytes.Equal(got.Csr, want.Csr) ||
		got.Ca != want.Ca || got.AccountUri != want.AccountUri || got.Profile != want.Profile || got.Serial != want.Serial ||
		!equalTime(got.NotBefore, want.NotBefore) || !equalTime(got.NotAfter, want.NotAfter) ||
		!equalTime(got.AriWindowStart, want.AriWindowStart) || !equalTime(got.AriWindowEnd, want.AriWindowEnd) ||
		got.State != want.State || got.SuccessorCertId != want.SuccessorCertId || !chainsEqual {
		return fmt.Errorf("read %+v, want %+v", got, want)
	}
	return nil
}

func caseCertsRoundTrip(ctx context.Context, store certsservice.CertsStore, hooks *CertsStoreSuiteHooks) error {
	base := certsSuiteBase()
	row := certsSuiteRow(sidecar.NewId(), base)
	if err := store.InsertCert(ctx, row); err != nil {
		return err
	}
	got, err := store.GetCert(ctx, row.CertId)
	if err != nil {
		return err
	}
	if err := certsSuiteSameRow(got, row); err != nil {
		return err
	}
	// every column a later step sets, and a custom domain's chain
	if err := certsSuiteIssue(ctx, store, row, certsservice.CertsCaLetsEncrypt, "fa1afe1", base.Add(time.Hour)); err != nil {
		return err
	}
	applied, err := store.TransitionCert(ctx, &certsservice.CertsTransition{
		CertId:         row.CertId,
		From:           []sidecar.TlsCertState{sidecar.TlsCertStateIssued},
		To:             sidecar.TlsCertStateIssued,
		AriWindowStart: base.Add(30 * 24 * time.Hour),
		AriWindowEnd:   base.Add(31 * 24 * time.Hour),
	})
	if err != nil || !applied {
		return fmt.Errorf("the ARI window: %v, %v", applied, err)
	}
	want := *row
	want.State = sidecar.TlsCertStateIssued
	want.Ca = string(certsservice.CertsCaLetsEncrypt)
	want.AccountUri = "https://ca.example/acct/1"
	want.Profile = "tlsserver"
	want.Serial = "fa1afe1"
	want.NotBefore = base.Add(time.Hour)
	want.NotAfter = base.Add(time.Hour + 45*24*time.Hour)
	want.AriWindowStart = base.Add(30 * 24 * time.Hour)
	want.AriWindowEnd = base.Add(31 * 24 * time.Hour)
	got, err = store.GetCert(ctx, row.CertId)
	if err != nil {
		return err
	}
	if err := certsSuiteSameRow(got, &want); err != nil {
		return err
	}
	chained := certsSuiteRow(sidecar.NewId(), base.Add(time.Minute))
	chained.Chain = [][]byte{certsSuiteRandom(300), certsSuiteRandom(280)}
	if err := store.InsertCert(ctx, chained); err != nil {
		return err
	}
	got, err = store.GetCert(ctx, chained.CertId)
	if err != nil {
		return err
	}
	return certsSuiteSameRow(got, chained)
}

func caseCertsInsertConflict(ctx context.Context, store certsservice.CertsStore, hooks *CertsStoreSuiteHooks) error {
	row := certsSuiteRow(sidecar.NewId(), certsSuiteBase())
	if err := store.InsertCert(ctx, row); err != nil {
		return err
	}
	if err := store.InsertCert(ctx, row); !errors.Is(err, certsservice.ErrCertsConflict) {
		return fmt.Errorf("a second insert answered %v", err)
	}
	return nil
}

func caseCertsNotFound(ctx context.Context, store certsservice.CertsStore, hooks *CertsStoreSuiteHooks) error {
	if _, err := store.GetCert(ctx, CertsIdAt(certsSuiteBase())); !errors.Is(err, certsservice.ErrCertsNotFound) {
		return fmt.Errorf("an unknown row answered %v", err)
	}
	return nil
}

func caseCertsNetworkRows(ctx context.Context, store certsservice.CertsStore, hooks *CertsStoreSuiteHooks) error {
	networkId := sidecar.NewId()
	base := certsSuiteBase()
	second := certsSuiteRow(networkId, base.Add(time.Minute))
	first := certsSuiteRow(networkId, base)
	other := certsSuiteRow(sidecar.NewId(), base.Add(30*time.Second))
	for _, row := range []*sidecar.TlsCertRecord{second, first, other} {
		if err := store.InsertCert(ctx, row); err != nil {
			return err
		}
	}
	rows, err := store.ListNetworkCerts(ctx, networkId)
	if err != nil {
		return err
	}
	if ids := certsSuiteIds(rows); !slices.Equal(ids, []sidecar.Id{first.CertId, second.CertId}) {
		return fmt.Errorf("listed %v", ids)
	}
	return nil
}

func caseCertsOpenOrder(ctx context.Context, store certsservice.CertsStore, hooks *CertsStoreSuiteHooks) error {
	base := certsSuiteBase()
	row := certsSuiteRow(sidecar.NewId(), base)
	if err := store.InsertCert(ctx, row); err != nil {
		return err
	}
	found, err := store.FindOpenOrder(ctx, row.NetworkId, row.SidecarId, row.SpkiSha256, row.IdentifierSetSha256)
	if err != nil || found == nil || found.CertId != row.CertId {
		return fmt.Errorf("the queued order: %+v, %v", found, err)
	}
	// another sidecar's key is another order
	found, err = store.FindOpenOrder(ctx, row.NetworkId, sidecar.NewId(), row.SpkiSha256, row.IdentifierSetSha256)
	if err != nil || found != nil {
		return fmt.Errorf("another sidecar found %+v, %v", found, err)
	}
	if err := certsSuiteIssue(ctx, store, row, certsservice.CertsCaGts, "b0b", base.Add(time.Hour)); err != nil {
		return err
	}
	found, err = store.FindOpenOrder(ctx, row.NetworkId, row.SidecarId, row.SpkiSha256, row.IdentifierSetSha256)
	if err != nil || found != nil {
		return fmt.Errorf("an issued order is still open: %+v, %v", found, err)
	}
	return nil
}

func caseCertsLiveBySerial(ctx context.Context, store certsservice.CertsStore, hooks *CertsStoreSuiteHooks) error {
	base := certsSuiteBase()
	row := certsSuiteRow(sidecar.NewId(), base)
	if err := store.InsertCert(ctx, row); err != nil {
		return err
	}
	serial := fmt.Sprintf("%x", certsSuiteRandom(12))
	if err := certsSuiteIssue(ctx, store, row, certsservice.CertsCaLetsEncrypt, serial, base); err != nil {
		return err
	}
	notAfter := base.Add(45 * 24 * time.Hour)
	found, err := store.FindLiveCertBySerial(ctx, row.NetworkId, serial, notAfter.Add(-time.Second))
	if err != nil || found == nil || found.CertId != row.CertId {
		return fmt.Errorf("inside its validity: %+v, %v", found, err)
	}
	found, err = store.FindLiveCertBySerial(ctx, row.NetworkId, serial, notAfter)
	if err != nil || found != nil {
		return fmt.Errorf("at its end: %+v, %v", found, err)
	}
	found, err = store.FindLiveCertBySerial(ctx, sidecar.NewId(), serial, base)
	if err != nil || found != nil {
		return fmt.Errorf("another network: %+v, %v", found, err)
	}
	return nil
}

func caseCertsTransition(ctx context.Context, store certsservice.CertsStore, hooks *CertsStoreSuiteHooks) error {
	row := certsSuiteRow(sidecar.NewId(), certsSuiteBase())
	if err := store.InsertCert(ctx, row); err != nil {
		return err
	}
	toOrdering := &certsservice.CertsTransition{
		CertId: row.CertId,
		From:   []sidecar.TlsCertState{sidecar.TlsCertStateQueued},
		To:     sidecar.TlsCertStateOrdering,
		Ca:     certsservice.CertsCaZeroSsl,
	}
	applied, err := store.TransitionCert(ctx, toOrdering)
	if err != nil || !applied {
		return fmt.Errorf("the first: %v, %v", applied, err)
	}
	applied, err = store.TransitionCert(ctx, toOrdering)
	if err != nil || applied {
		return fmt.Errorf("the second: %v, %v", applied, err)
	}
	got, err := store.GetCert(ctx, row.CertId)
	if err != nil {
		return err
	}
	if got.State != sidecar.TlsCertStateOrdering || got.Ca != string(certsservice.CertsCaZeroSsl) {
		return fmt.Errorf("read %+v", got)
	}
	applied, err = store.TransitionCert(ctx, &certsservice.CertsTransition{CertId: CertsIdAt(certsSuiteBase()), From: []sidecar.TlsCertState{sidecar.TlsCertStateQueued}, To: sidecar.TlsCertStateFailed})
	if err != nil || applied {
		return fmt.Errorf("an unknown row: %v, %v", applied, err)
	}
	return nil
}

func caseCertsSuccessor(ctx context.Context, store certsservice.CertsStore, hooks *CertsStoreSuiteHooks) error {
	base := certsSuiteBase()
	row := certsSuiteRow(sidecar.NewId(), base)
	next := certsSuiteNextOrder(row, base.Add(time.Hour))
	other := certsSuiteNextOrder(row, base.Add(2*time.Hour))
	for _, each := range []*sidecar.TlsCertRecord{row, next, other} {
		if err := store.InsertCert(ctx, each); err != nil {
			return err
		}
	}
	predecessor, err := store.GetPredecessor(ctx, next.CertId)
	if err != nil || predecessor != nil {
		return fmt.Errorf("before a link: %+v, %v", predecessor, err)
	}
	linked, err := store.SetSuccessor(ctx, row.CertId, next.CertId)
	if err != nil || !linked {
		return fmt.Errorf("the link: %v, %v", linked, err)
	}
	linked, err = store.SetSuccessor(ctx, row.CertId, other.CertId)
	if err != nil || linked {
		return fmt.Errorf("a second link: %v, %v", linked, err)
	}
	predecessor, err = store.GetPredecessor(ctx, next.CertId)
	if err != nil || predecessor == nil || predecessor.CertId != row.CertId || predecessor.SuccessorCertId != next.CertId {
		return fmt.Errorf("the predecessor: %+v, %v", predecessor, err)
	}
	return nil
}

func caseCertsSetIssuedBefore(ctx context.Context, store certsservice.CertsStore, hooks *CertsStoreSuiteHooks) error {
	base := certsSuiteBase()
	first := certsSuiteRow(sidecar.NewId(), base)
	second := certsSuiteNextOrder(first, base.Add(time.Hour))
	third := certsSuiteNextOrder(first, base.Add(2*time.Hour))
	for _, row := range []*sidecar.TlsCertRecord{first, second, third} {
		if err := store.InsertCert(ctx, row); err != nil {
			return err
		}
	}
	issued, err := store.SetIssuedBefore(ctx, first.IdentifierSetSha256, third.CertId)
	if err != nil || issued {
		return fmt.Errorf("with no serial: %v, %v", issued, err)
	}
	if err := certsSuiteIssue(ctx, store, second, certsservice.CertsCaLetsEncrypt, fmt.Sprintf("%x", certsSuiteRandom(8)), base.Add(time.Hour)); err != nil {
		return err
	}
	issued, err = store.SetIssuedBefore(ctx, first.IdentifierSetSha256, third.CertId)
	if err != nil || !issued {
		return fmt.Errorf("after an older row issued: %v, %v", issued, err)
	}
	// a newer certificate does not make an older order a repeat
	issued, err = store.SetIssuedBefore(ctx, first.IdentifierSetSha256, first.CertId)
	if err != nil || issued {
		return fmt.Errorf("before the first: %v, %v", issued, err)
	}
	return nil
}

func caseCertsSetOrders(ctx context.Context, store certsservice.CertsStore, hooks *CertsStoreSuiteHooks) error {
	base := certsSuiteBase()
	old := certsSuiteRow(sidecar.NewId(), base)
	recent := certsSuiteNextOrder(old, base.Add(3*24*time.Hour))
	elsewhere := certsSuiteNextOrder(old, base.Add(3*24*time.Hour+time.Minute))
	queued := certsSuiteNextOrder(old, base.Add(3*24*time.Hour+2*time.Minute))
	for _, row := range []*sidecar.TlsCertRecord{old, recent, elsewhere, queued} {
		if err := store.InsertCert(ctx, row); err != nil {
			return err
		}
	}
	for _, issue := range []struct {
		row *sidecar.TlsCertRecord
		ca  certsservice.CertsCa
	}{{old, certsservice.CertsCaLetsEncrypt}, {recent, certsservice.CertsCaLetsEncrypt}, {elsewhere, certsservice.CertsCaGts}} {
		if err := certsSuiteIssue(ctx, store, issue.row, issue.ca, fmt.Sprintf("%x", certsSuiteRandom(8)), certsFakeIdTime(issue.row.CertId)); err != nil {
			return err
		}
	}
	rows, err := store.ListSetOrders(ctx, old.IdentifierSetSha256, certsservice.CertsCaLetsEncrypt, base.Add(24*time.Hour))
	if err != nil {
		return err
	}
	if ids := certsSuiteIds(rows); !slices.Equal(ids, []sidecar.Id{recent.CertId}) {
		return fmt.Errorf("since a day on: %v", ids)
	}
	rows, err = store.ListSetOrders(ctx, old.IdentifierSetSha256, certsservice.CertsCaLetsEncrypt, base)
	if err != nil {
		return err
	}
	if ids := certsSuiteIds(rows); !slices.Equal(ids, []sidecar.Id{old.CertId, recent.CertId}) {
		return fmt.Errorf("since the start: %v", ids)
	}
	return nil
}

func caseCertsNewSetOrders(ctx context.Context, store certsservice.CertsStore, hooks *CertsStoreSuiteHooks) error {
	base := certsSuiteBase()
	firstOfSet := certsSuiteRow(sidecar.NewId(), base)
	repeat := certsSuiteNextOrder(firstOfSet, base.Add(time.Hour))
	inFlight := certsSuiteRow(sidecar.NewId(), base.Add(2*time.Hour))
	staleIssued := certsSuiteRow(sidecar.NewId(), base.Add(-10*24*time.Hour))
	otherCa := certsSuiteRow(sidecar.NewId(), base.Add(3*time.Hour))
	failed := certsSuiteRow(sidecar.NewId(), base.Add(4*time.Hour))
	for _, row := range []*sidecar.TlsCertRecord{firstOfSet, repeat, inFlight, staleIssued, otherCa, failed} {
		if err := store.InsertCert(ctx, row); err != nil {
			return err
		}
	}
	for _, issue := range []struct {
		row       *sidecar.TlsCertRecord
		ca        certsservice.CertsCa
		notBefore time.Time
	}{
		{firstOfSet, certsservice.CertsCaLetsEncrypt, base},
		{repeat, certsservice.CertsCaLetsEncrypt, base.Add(time.Hour)},
		{staleIssued, certsservice.CertsCaLetsEncrypt, base.Add(-10 * 24 * time.Hour)},
		{otherCa, certsservice.CertsCaGts, base.Add(3 * time.Hour)},
	} {
		if err := certsSuiteIssue(ctx, store, issue.row, issue.ca, fmt.Sprintf("%x", certsSuiteRandom(8)), issue.notBefore); err != nil {
			return err
		}
	}
	for _, step := range []*certsservice.CertsTransition{
		{CertId: inFlight.CertId, From: []sidecar.TlsCertState{sidecar.TlsCertStateQueued}, To: sidecar.TlsCertStateWaitingDns, Ca: certsservice.CertsCaLetsEncrypt},
		{CertId: failed.CertId, From: []sidecar.TlsCertState{sidecar.TlsCertStateQueued}, To: sidecar.TlsCertStateFailed, Ca: certsservice.CertsCaLetsEncrypt},
	} {
		if applied, err := store.TransitionCert(ctx, step); err != nil || !applied {
			return fmt.Errorf("to %s: %v, %v", step.To, applied, err)
		}
	}
	rows, err := store.ListNewSetOrders(ctx, certsservice.CertsCaLetsEncrypt, base.Add(-24*time.Hour))
	if err != nil {
		return err
	}
	own := certsSuiteOwn(rows, firstOfSet, repeat, inFlight, staleIssued, otherCa, failed)
	if !slices.Equal(own, []sidecar.Id{firstOfSet.CertId, inFlight.CertId}) {
		return fmt.Errorf("new-set orders %v, want the set's first and the one under way", own)
	}
	return nil
}

func caseCertsQueue(ctx context.Context, store certsservice.CertsStore, hooks *CertsStoreSuiteHooks) error {
	base := certsSuiteBase()
	networkId := sidecar.NewId()
	rows := []*sidecar.TlsCertRecord{}
	for index := range 4 {
		rows = append(rows, certsSuiteRow(networkId, base.Add(time.Duration(index)*time.Millisecond)))
	}
	for _, row := range rows {
		if err := store.InsertCert(ctx, row); err != nil {
			return err
		}
	}
	if applied, err := store.TransitionCert(ctx, &certsservice.CertsTransition{
		CertId: rows[1].CertId, From: []sidecar.TlsCertState{sidecar.TlsCertStateQueued}, To: sidecar.TlsCertStateOrdering, Ca: certsservice.CertsCaGts,
	}); err != nil || !applied {
		return fmt.Errorf("admitting one: %v, %v", applied, err)
	}
	// a cursor just before the case's range: a row of the shared queue before it is not read
	before := CertsIdAt(base.Add(-time.Millisecond))
	got, err := store.ListQueued(ctx, before, 1000)
	if err != nil {
		return err
	}
	if own := certsSuiteOwn(got, rows...); !slices.Equal(own, []sidecar.Id{rows[0].CertId, rows[2].CertId, rows[3].CertId}) {
		return fmt.Errorf("queued %v", own)
	}
	got, err = store.ListQueued(ctx, rows[2].CertId, 1000)
	if err != nil {
		return err
	}
	if own := certsSuiteOwn(got, rows...); !slices.Equal(own, []sidecar.Id{rows[3].CertId}) {
		return fmt.Errorf("after the third %v", own)
	}
	got, err = store.ListQueued(ctx, before, 1)
	if err != nil {
		return err
	}
	if len(got) != 1 {
		return fmt.Errorf("a count of one read %d", len(got))
	}
	return nil
}

func caseCertsPurge(ctx context.Context, store certsservice.CertsStore, hooks *CertsStoreSuiteHooks) error {
	// the epoch's own decade, so no other case's validity ends before the purge's time
	base := time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(certsSuiteRandom(1)[0]) * time.Hour)
	ended := certsSuiteRow(sidecar.NewId(), base)
	live := certsSuiteRow(sidecar.NewId(), base.Add(time.Minute))
	failed := certsSuiteRow(sidecar.NewId(), base.Add(2*time.Minute))
	for _, row := range []*sidecar.TlsCertRecord{ended, live, failed} {
		if err := store.InsertCert(ctx, row); err != nil {
			return err
		}
	}
	if err := certsSuiteIssue(ctx, store, ended, certsservice.CertsCaLetsEncrypt, fmt.Sprintf("%x", certsSuiteRandom(8)), base); err != nil {
		return err
	}
	if err := certsSuiteIssue(ctx, store, live, certsservice.CertsCaLetsEncrypt, fmt.Sprintf("%x", certsSuiteRandom(8)), base.Add(60*24*time.Hour)); err != nil {
		return err
	}
	if applied, err := store.TransitionCert(ctx, &certsservice.CertsTransition{
		CertId: failed.CertId, From: []sidecar.TlsCertState{sidecar.TlsCertStateQueued}, To: sidecar.TlsCertStateFailed,
	}); err != nil || !applied {
		return fmt.Errorf("failing one: %v, %v", applied, err)
	}
	// ended's validity ends 45 days in; the purge counts from 30 days after that
	purgeBefore := base.Add(45*24*time.Hour + time.Second)
	removedCount, err := store.PurgeEnded(ctx, purgeBefore)
	if err != nil {
		return err
	}
	if removedCount < 1 {
		return fmt.Errorf("purged %d", removedCount)
	}
	if _, err := store.GetCert(ctx, ended.CertId); !errors.Is(err, certsservice.ErrCertsNotFound) {
		return fmt.Errorf("the ended row: %v", err)
	}
	for _, kept := range []*sidecar.TlsCertRecord{live, failed} {
		if _, err := store.GetCert(ctx, kept.CertId); err != nil {
			return fmt.Errorf("a row the purge must keep: %v", err)
		}
	}
	return nil
}

func caseCertsEphemeral(ctx context.Context, store certsservice.CertsStore, hooks *CertsStoreSuiteHooks) error {
	clientId := sidecar.NewId()
	ephemeral, err := store.ClientEphemeral(ctx, clientId)
	if err != nil || ephemeral {
		return fmt.Errorf("an unknown client: %v, %v", ephemeral, err)
	}
	if hooks.MarkEphemeral == nil {
		return nil
	}
	if err := hooks.MarkEphemeral(ctx, clientId); err != nil {
		return err
	}
	ephemeral, err = store.ClientEphemeral(ctx, clientId)
	if err != nil || !ephemeral {
		return fmt.Errorf("a marked client: %v, %v", ephemeral, err)
	}
	return nil
}
