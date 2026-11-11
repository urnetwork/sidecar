// MAIL-M8-02 end to end on T2: sidecar.MailVault over a real mailbox on evsservice (the deposit world's, record-class
// and owner-bound), so its writes, its History of slots, its ERASE and its removal go through the engine as a device's
// would, and everything the server is sent or holds is read back for the entry's secrets.

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

// Holds the world's owner a consented device of any member, as the owner's device's state would.
type mailVaultWorldConsent struct {
	ownerId sidecar.Id
}

func (self mailVaultWorldConsent) Consented(sidecarId sidecar.Id, memberId sidecar.Id) bool {
	return sidecarId == self.ownerId
}

// A device's transport onto the deposit world: every request's URL and body kept, and before, when set, run on a
// request before the world serves it, so a test lands another device's write ahead of this one's push.
type mailVaultWorldTransport struct {
	world *depositWorld

	stateLock sync.Mutex
	captured  [][]byte
	before    func(request *http.Request) error
}

func (self *mailVaultWorldTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	captured := []byte(request.URL.String())
	if request.Body != nil {
		body, err := io.ReadAll(request.Body)
		request.Body.Close()
		if err != nil {
			return nil, err
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		captured = append(append(captured, 0), body...)
	}
	before := func() func(request *http.Request) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.captured = append(self.captured, captured)
		return self.before
	}()
	if before != nil {
		if err := before(request); err != nil {
			return nil, err
		}
	}
	return self.world.RoundTrip(request)
}

// Sets the hook, nil to clear it.
func (self *mailVaultWorldTransport) setBefore(before func(request *http.Request) error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.before = before
}

// Every request this transport carried.
func (self *mailVaultWorldTransport) requests() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([][]byte{}, self.captured...)
}

// A device of the owner with a fresh store, as depositWorld.deviceWith makes one, its waits answered at once, on
// transport.
func mailVaultWorldClient(t *testing.T, world *depositWorld, transport http.RoundTripper) *sidecar.EvsClient {
	t.Helper()
	signer := world.owner
	gkmClient := world.gkm.Client(signer.SidecarId, signer.Sign)
	gkmClient.AuthAdvanced(world.view)
	identity := &sidecar.SidecarIdentity{NetworkId: world.networkId, SidecarId: signer.SidecarId, ClientId: world.clientId, Generation: 1, IdentityPublicKey: signer.PublicKey()}
	client, err := sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: world.networkId,
		EvsUrl:    "https://evs.example",
		Transport: transport,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			connectSidecarId := connect.Id(signer.SidecarId)
			return world.host.Authenticator.Issue(&sidecar.Principal{
				NetworkId: connect.Id(world.networkId), ClientId: connect.Id(world.clientId), SidecarId: &connectSidecarId,
				Audience: evsservice.EvsAudience, Scopes: scopes, IssuedAt: world.clock.Now(), ExpiresAt: world.clock.Now().Add(15 * time.Minute),
			}), nil
		},
		Sign:     sidecar.EvsSignFunction(signer.Sign),
		Identity: func() *sidecar.SidecarIdentity { return identity },
		Gkm:      gkmClient,
		Store:    NewFakeStore().Root(),
		Config:   func() sidecar.GkmAuthView { return world.view },
		Clock:    &epochDeviceClock{clock: world.clock},
		Log:      sidecar.NewNoopLogger(),
		Settings: sidecar.DefaultEvsSettings(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

// The owner's vault over a device of its own, its transport capturing.
func mailVaultWorldVault(t *testing.T, world *depositWorld) (*sidecar.MailVault, *sidecar.EvsRepo, *mailVaultWorldTransport) {
	t.Helper()
	transport := &mailVaultWorldTransport{world: world}
	repo := mailVaultWorldClient(t, world, transport).Repo(world.repoId)
	vault, err := sidecar.NewMailVault(&sidecar.MailVaultArgs{
		Repo: repo, OwnerMemberId: sidecar.NewId(), SidecarId: world.owner.SidecarId,
		Authority: mailVaultWorldConsent{ownerId: world.owner.SidecarId}, Clock: &epochDeviceClock{clock: world.clock},
	})
	if err != nil {
		t.Fatal(err)
	}
	return vault, repo, transport
}

// An entry written through evs in more versions than one chain holds, so its versions use more than one slot, is
// deleted, its removal lost as a crash would lose it: the one ERASE names every slot, a fresh device of the owner lists
// nothing and opens none of the versions History walks, its resume removes the path under that erasure, a second
// delete is done already, and no password, earlier password, totp secret or address appears in any request a device
// sent or in anything the server stores.
func TestMailVaultDeleteLeavesNoVersionOpenableEndToEnd(t *testing.T) {
	world := newDepositWorld(t)
	ctx := context.Background()
	vault, _, writerTransport := mailVaultWorldVault(t, world)
	const address = "shop@otter-4821.acme.root.example"
	const passwordCanary, totpCanary = "vault password canary 9f3e", "vault totp canary 1d7c"
	entry := &protocol.VaultEntry{
		Address: address, Title: "a synthetic shop", Username: address, Password: passwordCanary + " 0",
		Totp: &protocol.VaultTotp{Secret: []byte(totpCanary), Algorithm: protocol.VaultTotpAlgorithm_VAULT_TOTP_SHA1, Digits: 6, Period: 30},
		Urls: []string{"https://shop.example/login"},
	}
	written, err := vault.PutVaultEntry(ctx, entry)
	if err != nil {
		t.Fatal(err)
	}
	// a chain holds EvsChainMaxRecordCount records, so this many writes start a second
	for index := 1; index <= sidecar.EvsChainMaxRecordCount+1; index += 1 {
		update := proto.Clone(written).(*protocol.VaultEntry)
		update.Password = fmt.Sprintf("%s %d", passwordCanary, index)
		if written, err = vault.PutVaultEntry(ctx, update); err != nil {
			t.Fatalf("update %d: %v", index, err)
		}
	}
	if err := vault.NoteUsedAt(ctx, address, "mail.shop.example", world.clock.Now()); err != nil {
		t.Fatal(err)
	}
	entryId, _ := sidecar.IdFromBytes(written.GetEntryId())
	path := sidecar.MailVaultPath(entryId)

	reader, readerRepo, readerTransport := mailVaultWorldVault(t, world)
	listed, err := reader.VaultEntries(ctx)
	if err != nil || len(listed) != 1 || len(listed[0].GetUsedAt()) != 1 {
		t.Fatalf("another device of the owner lists %d entries, %v", len(listed), err)
	}
	withoutUse := proto.Clone(listed[0]).(*protocol.VaultEntry)
	withoutUse.UsedAt = nil
	if !proto.Equal(withoutUse, written) || len(written.GetPasswordHistory()) != sidecar.EvsChainMaxRecordCount+1 {
		t.Fatal("another device of the owner reads another entry than was written")
	}
	if usedAts, err := reader.UsedAt(ctx, entryId); err != nil || len(usedAts) != 1 || usedAts[0].GetRegistrableDomain() != "shop.example" {
		t.Fatalf("used at %v, %v", usedAts, err)
	}
	history, err := readerRepo.History(ctx, &sidecar.EvsReadArgs{Path: path})
	if err != nil || len(history.Versions) != sidecar.EvsChainMaxRecordCount+3 {
		t.Fatalf("history %v, %v", history, err)
	}
	slotIds := map[sidecar.Id]bool{}
	for _, version := range history.Versions {
		if len(version.SlotIds) == 0 {
			t.Fatalf("version %d names no slot", version.Version)
		}
		for _, slotId := range version.SlotIds {
			slotIds[slotId] = true
		}
	}
	if len(slotIds) < 2 {
		t.Fatalf("%d slots across %d versions", len(slotIds), len(history.Versions))
	}

	// the removal's push never reaches evs, as a crash between the ERASE and the removal leaves it
	lost := errors.New("a removal lost to a crash")
	writerTransport.setBefore(func(request *http.Request) error {
		if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/push") {
			return lost
		}
		return nil
	})
	if err := vault.DeleteVaultEntry(ctx, entryId); !errors.Is(err, lost) {
		t.Fatalf("the delete whose removal was lost: %v", err)
	}
	writerTransport.setBefore(nil)
	fresh, freshRepo, freshTransport := mailVaultWorldVault(t, world)
	if entries, err := fresh.VaultEntries(ctx); err != nil || len(entries) != 0 {
		t.Fatalf("a fresh device lists %d entries, %v", len(entries), err)
	}
	erasures, err := freshRepo.ReadErasures(ctx, 0)
	if err != nil || len(erasures) != 1 || !erasures[0].Complete || string(erasures[0].Note) != path || len(erasures[0].Keys) != len(slotIds) {
		t.Fatalf("erasures %v, %v", erasures, err)
	}
	for _, key := range erasures[0].Keys {
		if !slotIds[key.SlotId] || key.KeyIndex != 0 {
			t.Fatalf("an erased key no version names: %v", key)
		}
	}
	standing, err := freshRepo.History(ctx, &sidecar.EvsReadArgs{Path: path})
	if err != nil || len(standing.Versions) != len(history.Versions) || standing.Versions[0].Removed {
		t.Fatalf("the standing path's history: %v", err)
	}
	for _, version := range standing.Versions {
		out := &bytes.Buffer{}
		if _, err := freshRepo.ReadHead(ctx, &sidecar.EvsReadArgs{Path: path, Version: version.Version}, out); err == nil {
			t.Fatalf("version %d opened after the ERASE", version.Version)
		}
	}
	if err := fresh.ResumeVaultDeletions(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := freshRepo.ReadHead(ctx, &sidecar.EvsReadArgs{Path: path}, &bytes.Buffer{}); !errors.Is(err, sidecar.ErrEvsPathAbsent) {
		t.Fatalf("the path after the resume: %v", err)
	}
	if again, err := freshRepo.ReadErasures(ctx, 0); err != nil || len(again) != 1 {
		t.Fatalf("the resume committed another ERASE: %d, %v", len(again), err)
	}
	if err := vault.DeleteVaultEntry(ctx, entryId); err != nil {
		t.Fatalf("a second delete: %v", err)
	}

	captured := [][]byte{}
	for _, transport := range []*mailVaultWorldTransport{writerTransport, readerTransport, freshTransport} {
		captured = append(captured, transport.requests()...)
	}
	if len(captured) < 3*sidecar.EvsChainMaxRecordCount {
		t.Fatalf("only %d requests captured", len(captured))
	}
	for key, value := range world.host.Blobs.Dump() {
		captured = append(captured, []byte(key), value)
	}
	for _, canary := range []string{passwordCanary, totpCanary, "canary", address} {
		for _, seen := range captured {
			if bytes.Contains(seen, []byte(canary)) {
				t.Fatalf("%q is in a request or in what the server holds", canary)
			}
		}
	}
	for _, seen := range writerTransport.requests() {
		if url, _, _ := strings.Cut(string(seen), "\x00"); strings.Contains(url, "vault") {
			t.Fatalf("a request's URL names the vault: %s", url)
		}
	}
}

// Two devices of the owner write one entry, the desktop's use landing between the phone's read and its push: evs's
// CAS refuses the phone's push, the phone reads again, and both changes stand, the person's edit and the use.
func TestMailVaultWritesThroughEvsHoldToTheVersionRead(t *testing.T) {
	world := newDepositWorld(t)
	ctx := context.Background()
	phone, _, phoneTransport := mailVaultWorldVault(t, world)
	desktop, _, _ := mailVaultWorldVault(t, world)
	const address = "shop@otter-4821.acme.root.example"
	written, err := phone.PutVaultEntry(ctx, &protocol.VaultEntry{Address: address, Title: "a synthetic shop", Password: "a synthetic password"})
	if err != nil {
		t.Fatal(err)
	}
	entryId, _ := sidecar.IdFromBytes(written.GetEntryId())
	pushes := 0
	phoneTransport.setBefore(func(request *http.Request) error {
		if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/push") {
			return nil
		}
		pushes += 1
		if pushes == 1 {
			if err := desktop.NoteUsedAt(ctx, address, "shop.example", world.clock.Now()); err != nil {
				return fmt.Errorf("the desktop's use: %w", err)
			}
		}
		return nil
	})
	update := proto.Clone(written).(*protocol.VaultEntry)
	update.Notes = "an edit on the phone"
	edited, err := phone.PutVaultEntry(ctx, update)
	phoneTransport.setBefore(nil)
	if err != nil {
		t.Fatal(err)
	}
	if pushes != 2 {
		t.Fatalf("%d pushes from the phone, not the refused one and the one after it", pushes)
	}
	read, err := desktop.VaultEntry(ctx, entryId)
	if err != nil || read.GetNotes() != update.GetNotes() || len(read.GetUsedAt()) != 1 || !proto.Equal(read, edited) {
		t.Fatalf("the entry after the race: %v, %v", read, err)
	}
}

// A vault path removed outside the vault, with no ERASE before it, is never answered shredded while its versions
// stand unerased: History of a removed path reaches none of its earlier versions (question
// mail-m8-02-history-of-a-removed-path), so the delete refuses and erases nothing; once History walks them, the delete
// erases every one, and this holds either way.
func TestMailVaultDeleteOfAPathRemovedUnerasedFailsClosed(t *testing.T) {
	world := newDepositWorld(t)
	ctx := context.Background()
	vault, repo, _ := mailVaultWorldVault(t, world)
	written, err := vault.PutVaultEntry(ctx, &protocol.VaultEntry{Address: "shop@otter-4821.acme.root.example", Password: "a synthetic password"})
	if err != nil {
		t.Fatal(err)
	}
	entryId, _ := sidecar.IdFromBytes(written.GetEntryId())
	if _, err := repo.Write(ctx, &sidecar.EvsWriteArgs{Path: sidecar.MailVaultPath(entryId), Remove: true}); err != nil {
		t.Fatal(err)
	}
	err = vault.DeleteVaultEntry(ctx, entryId)
	erasures, readErr := repo.ReadErasures(ctx, 0)
	if readErr != nil {
		t.Fatal(readErr)
	}
	switch {
	case errors.Is(err, sidecar.ErrMailVaultNotShreddable):
		if len(erasures) != 0 {
			t.Fatalf("a refused delete committed %d ERASEs", len(erasures))
		}
	case err == nil:
		if len(erasures) != 1 || len(erasures[0].Keys) == 0 {
			t.Fatalf("a delete answered done with %d ERASEs", len(erasures))
		}
	default:
		t.Fatalf("the delete: %v", err)
	}
}
