//go:build !sidecar_http && !js

// CORE-M2-01 on the public API, with sidecartest's Net and FakeAuthority: nothing is admitted before a SidecarAdmit
// names the sidecar, tagged and ephemeral enrollments before base 1 surface no_genesis, the safety number's vector,
// and an invite's anchor recorded at enrollment refusing another genesis (S1).

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A Net with one sidecar enrolled and Online, and its network record.
func newAdmissionTestSidecar(t *testing.T) (*sidecartest.Net, *sidecartest.TestSidecar, sidecar.SidecarNetworkRecord) {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	laptop, err := net.AddSidecar("laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	record, ok := laptop.NetworkRecord()
	if !ok {
		t.Fatal("no network record")
	}
	return net, laptop, record
}

// §5.6: until a SidecarAdmit names it, a sidecar is not admitted, so it gets no peer, wrap or grant, whatever api
// says: with no verified state, with a state that does not name it, after its revocation, and past an agent's
// not_after. Admitted only between.
func TestNothingBeforeAdmission(t *testing.T) {
	net, laptop, record := newAdmissionTestSidecar(t)
	running := laptop.Sidecar()
	if running.Admitted() {
		t.Fatal("admitted with no verified state")
	}
	authority := sidecartest.NewFakeAuthority()
	remove := running.InstallAuthority(authority)
	defer remove()
	if running.Admitted() {
		t.Fatal("admitted by a state that does not name it")
	}

	memberId := sidecar.NewId()
	authority.AdmitSidecar(&sidecartest.FakeAuthorityAdmission{SidecarId: record.SidecarId, MemberId: memberId})
	if !running.Admitted() {
		t.Fatal("not admitted once a SidecarAdmit names it")
	}
	authority.EditSidecar(record.SidecarId, func(row *bridge.SidecarRow) { row.ParkedAt = 5 })
	if !running.Admitted() {
		t.Error("a parked admission is still an admission; consent gates its owner-bound reads")
	}
	authority.EditSidecar(record.SidecarId, func(row *bridge.SidecarRow) { row.RevokedAt = 6 })
	if running.Admitted() {
		t.Error("admitted after its revocation")
	}

	agent, err := net.AddSidecar("agent", nil)
	if err != nil {
		t.Fatal(err)
	}
	agentRecord, _ := agent.NetworkRecord()
	defer agent.Sidecar().InstallAuthority(authority)()
	authority.AdmitSidecar(&sidecartest.FakeAuthorityAdmission{
		SidecarId: agentRecord.SidecarId,
		TagIds:    []sidecar.Id{sidecar.NewId()},
		NotAfter:  net.Clock().Now().Add(time.Hour).UnixMilli(),
	})
	if !agent.Sidecar().Admitted() {
		t.Fatal("an agent before its not_after")
	}
	net.Clock().Advance(time.Hour)
	if agent.Sidecar().Admitted() {
		t.Error("an agent past its not_after")
	}

	remove()
	if running.Admitted() {
		t.Error("admitted once the verified state is removed")
	}
}

// §7.9's genesis row: a tagged or ephemeral enrollment before base 1 is refused no_genesis, which Enroll surfaces by
// name, and nothing is kept.
func TestNoGenesisSurfaces(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	laptop, err := net.StartSidecar("laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := laptop.AwaitState(ctx, sidecar.SidecarStateUnenrolled); err != nil {
		t.Fatal(err)
	}
	for _, args := range []*sidecartest.FakeApiAuthKeyArgs{
		{NetworkId: net.DefaultNetworkId(), Tagged: true},
		{NetworkId: net.DefaultNetworkId(), Ephemeral: true},
	} {
		authKey := laptop.Api.NewAuthKey(args)
		enrollErr := &sidecar.SidecarEnrollError{}
		err := laptop.EnrollWith(ctx, &sidecar.SidecarEnrollCredential{AuthKey: authKey})
		if !errors.As(err, &enrollErr) || enrollErr.Reason != sidecar.SidecarEnrollNoGenesis {
			t.Errorf("%+v: %v", args, err)
		}
	}
	if records := laptop.Instance().Networks(); len(records) != 0 {
		t.Errorf("kept %+v", records)
	}
}

// plan-CORE-safety-number's vector, which every leg answers alike: genesis_sha256 0x01..0x20 and identity key
// 0x21..0x40, computed apart from this code.
func TestSafetyNumberVector(t *testing.T) {
	genesisSha256 := make([]byte, 32)
	identityKey := make([]byte, 32)
	for i := range 32 {
		genesisSha256[i] = byte(i + 1)
		identityKey[i] = byte(i + 33)
	}
	number, err := sidecar.SafetyNumber(genesisSha256, identityKey)
	if err != nil {
		t.Fatal(err)
	}
	if want := "565625921663244531324035006436199424699255817544032889870537"; number != want {
		t.Fatalf("%s, want %s", number, want)
	}
	formatted := sidecar.FormatSafetyNumber(number)
	lines := strings.Split(formatted, "\n")
	if len(lines) != 3 || lines[0] != "56562 59216 63244 53132" || len(strings.Fields(lines[2])) != 4 {
		t.Errorf("%q", formatted)
	}
	if _, err := sidecar.SafetyNumber(genesisSha256[:31], identityKey); !errors.Is(err, sidecar.ErrSidecarSafetyNumber) {
		t.Errorf("a short hash: %v", err)
	}
}

// S1: an invite's anchor is recorded at enrollment, and the log a ConfigClient checks against it must chain to that
// genesis and not fall below its head; the sidecar's safety number is over that genesis.
func TestAnchorPassedToConfigClient(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	laptop, err := net.StartSidecar("laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := laptop.AwaitState(ctx, sidecar.SidecarStateUnenrolled); err != nil {
		t.Fatal(err)
	}
	genesis := sha256.Sum256([]byte("a synthetic signed genesis"))
	headChain := sha256.Sum256([]byte("a synthetic head"))
	authKey := laptop.Api.NewAuthKey(&sidecartest.FakeApiAuthKeyArgs{NetworkId: net.DefaultNetworkId()})
	err = laptop.EnrollWith(ctx, &sidecar.SidecarEnrollCredential{
		AuthKey: authKey,
		Anchor:  &sidecar.SidecarEnrollAnchor{GenesisSha256: genesis[:], HeadVersion: 7, HeadChain: headChain[:]},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := laptop.AwaitState(ctx, sidecar.SidecarStateOnline); err != nil {
		t.Fatal(err)
	}
	anchor, err := laptop.Sidecar().Anchor()
	if err != nil {
		t.Fatal(err)
	}
	if anchor.Source != sidecar.SidecarAnchorInvite || !bytes.Equal(anchor.GenesisSha256, genesis[:]) || anchor.Head.GetVersion() != 7 {
		t.Fatalf("anchor %+v", anchor)
	}
	other := sha256.Sum256([]byte("another network's genesis"))
	if err := anchor.Check(other[:], &bridge.AuthPin{Version: 9, Chain: headChain[:]}); !errors.Is(err, sidecar.ErrSidecarAnchorMismatch) {
		t.Errorf("another genesis: %v", err)
	}
	if err := anchor.Check(genesis[:], &bridge.AuthPin{Version: 6, Chain: headChain[:]}); !errors.Is(err, sidecar.ErrSidecarAnchorMismatch) {
		t.Errorf("a lower pin: %v", err)
	}
	if err := anchor.Check(genesis[:], &bridge.AuthPin{Version: 7, Chain: other[:]}); !errors.Is(err, sidecar.ErrSidecarAnchorMismatch) {
		t.Errorf("another chain at the head: %v", err)
	}
	if err := anchor.Check(genesis[:], &bridge.AuthPin{Version: 12, Chain: other[:]}); err != nil {
		t.Errorf("past the head: %v", err)
	}
	if err := laptop.Sidecar().TrustFirstUse(other[:]); !errors.Is(err, sidecar.ErrSidecarAnchorMismatch) {
		t.Errorf("first use over a recorded anchor: %v", err)
	}
	number, err := laptop.Sidecar().SafetyNumber()
	if err != nil {
		t.Fatal(err)
	}
	identity := laptop.Sidecar().Identity()
	if want, _ := sidecar.SafetyNumber(genesis[:], identity.IdentityPublicKey); number != want {
		t.Errorf("%s, want %s", number, want)
	}
}

// A `ur login` device with no anchor trusts the first genesis it is shown, and refuses any other after.
func TestFirstUseAnchorsOnce(t *testing.T) {
	_, laptop, _ := newAdmissionTestSidecar(t)
	running := laptop.Sidecar()
	if _, err := running.Anchor(); !errors.Is(err, sidecar.ErrSidecarStoreAbsent) {
		t.Fatalf("an anchor with none brought: %v", err)
	}
	genesis := sha256.Sum256([]byte("the first genesis shown"))
	if err := running.TrustFirstUse(genesis[:]); err != nil {
		t.Fatal(err)
	}
	if err := running.TrustFirstUse(genesis[:]); err != nil {
		t.Errorf("the same genesis again: %v", err)
	}
	other := sha256.Sum256([]byte("another"))
	if err := running.TrustFirstUse(other[:]); !errors.Is(err, sidecar.ErrSidecarAnchorMismatch) {
		t.Errorf("another genesis: %v", err)
	}
	if anchor, err := running.Anchor(); err != nil || anchor.Source != sidecar.SidecarAnchorFirstUse {
		t.Errorf("%+v %v", anchor, err)
	}
}

// §22.7's canaries for both of a bundle's seeds on CLI enrollment: a pre-approved key's bundle is split off before
// anything reads the key and is refused whole until the log can give its Delegation's row, and neither seed reaches a
// log, the environment or a frame.
func TestDelegationSeedsNeverLeaveTheDevice(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	laptop, err := net.StartSidecar("laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := laptop.AwaitState(ctx, sidecar.SidecarStateUnenrolled); err != nil {
		t.Fatal(err)
	}
	capture := net.Capture()
	signingSeed := capture.Canary("delegation signing seed")
	readerSeed := capture.Canary("delegation reader seed")
	genesis := sha256.Sum256([]byte("a synthetic signed genesis"))
	head := sha256.Sum256([]byte("a synthetic head"))
	bundle, err := proto.Marshal(&protocol.AuthKeyBundle{
		Version:               1,
		GenesisSha256:         genesis[:],
		Head:                  &bridge.AuthPin{Version: 3, Chain: head[:]},
		DelegationId:          sidecar.NewId().Bytes(),
		DelegationSigningSeed: signingSeed,
		DelegationReaderSeed:  readerSeed,
		TagIds:                [][]byte{sidecar.NewId().Bytes()},
	})
	if err != nil {
		t.Fatal(err)
	}
	authKey := laptop.Api.NewAuthKey(&sidecartest.FakeApiAuthKeyArgs{NetworkId: net.DefaultNetworkId()})
	err = laptop.EnrollWith(ctx, &sidecar.SidecarEnrollCredential{AuthKey: authKey + "#" + base64.RawURLEncoding.EncodeToString(bundle)})
	if !errors.Is(err, sidecar.ErrSidecarEnrollBundle) {
		t.Fatalf("a bundle: %v", err)
	}
	if laptop.Api.RouteCount("POST /network/enroll") != 0 {
		t.Error("a request was sent for a key holding a bundle")
	}
	if findings := capture.Scan(); len(findings) != 0 {
		t.Errorf("%v", findings)
	}
}
