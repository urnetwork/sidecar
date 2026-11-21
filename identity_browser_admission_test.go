//go:build !sidecar_http && !js

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

type testBrowserAuthority struct {
	*testActAuthority
	mailbox *protocol.AclRepo
}

func (a *testBrowserAuthority) BrowserMailbox(member, mailbox Id) *protocol.AclRepo {
	if bytes.Equal(a.mailbox.GetOwnerMemberId(), member.Bytes()) && bytes.Equal(a.mailbox.GetRepoId(), mailbox.Bytes()) {
		return a.mailbox
	}
	return nil
}

type testBrowserLookup struct {
	delta         *testDeltaApi
	reply         *sidecarIdentityReply
	mode          string
	landAdmission func(*bridge.Signed)
	fallback      http.RoundTripper
}

func (a *testBrowserLookup) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == "GET" && r.URL.Path == "/sidecar/identity/"+a.reply.SidecarId.String() && r.URL.Query().Get("browser_admission") == a.mode {
		return testApiAnswer(http.StatusOK, a.reply)
	}
	if a.fallback != nil {
		return a.fallback.RoundTrip(r)
	}
	reply, err := a.delta.RoundTrip(r)
	if err == nil && reply.StatusCode == http.StatusOK && a.landAdmission != nil {
		posts := a.delta.postsSoFar()
		var signed bridge.Signed
		if proto.Unmarshal(posts[len(posts)-1], &signed) == nil && bridge.SignedType(signed.GetType()) == bridge.SignedType_SIGNED_SIDECAR_ADMIT {
			a.landAdmission(&signed)
		}
	}
	return reply, err
}

func TestBrowserApprovalsMakeTheExpectedReposReadableOnTheVerifiedLog(t *testing.T) {
	vault, mailbox := NewId(), NewId()
	world := newTestCleanupWorld(t, 100, func(w *testCleanupWorld) {
		for _, repo := range []struct {
			id   Id
			kind protocol.RepoKind
		}{{vault, protocol.RepoKind_REPO_KIND_VAULT}, {mailbox, protocol.RepoKind_REPO_KIND_MAILBOX}} {
			w.net.mustPost(w.net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: w.net.header(), RepoId: repo.id.Bytes(), Kind: repo.kind})
		}
	})
	running := world.sidecar
	genesis := world.net.log.State().genesisChain
	if err := running.TrustFirstUse(genesis[:]); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{BrowserAdmissionPage, BrowserAdmissionBurner} {
		t.Run(mode, func(t *testing.T) {
			target := NewId()
			signed, err := NewSidecarIdentityBinding(&SidecarIdentityBinding{NetworkId: world.net.networkId, SidecarId: target,
				ClientId: NewId(), Generation: 1, IssuedAt: running.clock.Now()}, bytes.Repeat([]byte{mode[0]}, 32), bytes.Repeat([]byte{mode[0] + 1}, 32))
			if err != nil {
				t.Fatal(err)
			}
			identity, err := VerifySidecarIdentityBinding(signed)
			if err != nil {
				t.Fatal(err)
			}
			running.sidecarApi.setTransport(&testBrowserLookup{mode: mode, fallback: world.api, reply: &sidecarIdentityReply{SidecarId: &target, Status: "active",
				IdentityAlg: configIdentityAlgEd25519, IdentityPublicKey: identity.IdentityPublicKey, Binding: signed, BrowserAdmission: mode}})
			terms := BrowserAdmissionTerms{Mode: mode}
			now := running.clock.Now()
			if mode == BrowserAdmissionBurner {
				terms.MailboxId = mailbox
				terms.NotAfterMs = now.Add(time.Hour).UnixMilli()
			}
			preview, err := running.PreviewBrowserAdmission(t.Context(), target, terms)
			if err != nil {
				t.Fatal(err)
			}
			if err := running.ConfirmBrowserAdmission(t.Context(), target, *preview, nil); err != nil {
				t.Fatal(err)
			}
			state := world.catchUp()
			acl, err := state.Acl()
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(acl.RepoReaders(mailbox, now), target) || slices.Contains(acl.RepoWriters(mailbox, now), target) {
				t.Fatal("incorrect mailbox rights")
			}
			if mode == BrowserAdmissionPage {
				if !acl.ConsentedFor(target, world.net.ownerMemberId) || !slices.Contains(acl.RepoReaders(vault, now), target) || slices.Contains(acl.RepoWriters(vault, now), target) {
					t.Fatal("page cannot read its member's existing vault with read-only consent")
				}
			} else if slices.Contains(acl.RepoReaders(vault, now), target) || slices.Contains(acl.RepoReaders(mailbox, now.Add(2*time.Hour)), target) {
				t.Fatal("burner could read past the approved mailbox or expiry")
			}
		})
	}
}

func TestBrowserFollowupWaitsForItsOwnVerifiedAdmission(t *testing.T) {
	world := newAlarmTestWorld(t)
	world.consentSelf()
	running := world.sidecar
	api := running.sidecarApi.Transport().(*absoluteUrlTransport).transport.(*testDeltaApi)
	target := NewId()
	act, err := running.newAct(SidecarActConfirmed)
	if err != nil {
		t.Fatal(err)
	}
	act.browserTarget = &target
	if err := act.Add(bridge.SignedType_SIGNED_SIDECAR_ADMIT, &protocol.SidecarAdmit{SidecarId: target.Bytes(), MemberId: world.memberId.Bytes()}); err != nil {
		t.Fatal(err)
	}
	if err := act.Add(bridge.SignedType_SIGNED_OWNER_CONFIRM, &protocol.OwnerConfirm{SidecarId: target.Bytes()}); err != nil {
		t.Fatal(err)
	}
	// A receipt alone does not confirm the signer's view of the admission.
	if _, err := act.Run(t.Context(), nil); !errors.Is(err, ErrSidecarActPending) {
		t.Fatalf("waiting for the follower: %v", err)
	}
	if got := len(api.postsSoFar()); got != 1 {
		t.Fatalf("before the verified admission: %d posts", got)
	}
	// A different admission won the sequencer race. Reload the sealed retry as a restarted daemon does.
	world.admit(target, world.memberId)
	if err := running.PostPendingStatements(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := len(api.postsSoFar()); got != 1 {
		t.Fatalf("after another admission won: %d posts", got)
	}
	pending, err := running.pendingStatements()
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending follow-up after losing the race: %d %v", len(pending), err)
	}
}

func TestBrowserApprovalConfirmsTypedScopeAndReplaysGrant(t *testing.T) {
	for _, mode := range []string{BrowserAdmissionPage, BrowserAdmissionBurner} {
		t.Run(mode, func(t *testing.T) {
			world := newAlarmTestWorld(t)
			running := world.sidecar
			identity := running.currentIdentity()
			target, mailbox := NewId(), NewId()
			authority := &testBrowserAuthority{testActAuthority: world.authority, mailbox: &protocol.AclRepo{
				RepoId: mailbox.Bytes(), OwnerMemberId: world.memberId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_MAILBOX}}
			t.Cleanup(running.InstallAuthority(authority))
			anchor := sha256.Sum256([]byte("genesis"))
			if err := running.TrustFirstUse(anchor[:]); err != nil {
				t.Fatal(err)
			}
			keys, err := NewSidecarIdentityBinding(&SidecarIdentityBinding{NetworkId: identity.NetworkId, SidecarId: target, ClientId: NewId(),
				Generation: 1, IssuedAt: world.clock.Now()}, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
			if err != nil {
				t.Fatal(err)
			}
			verified, err := VerifySidecarIdentityBinding(keys)
			if err != nil {
				t.Fatal(err)
			}
			number, err := SafetyNumber(anchor[:], verified.IdentityPublicKey)
			if err != nil {
				t.Fatal(err)
			}
			api := &testBrowserLookup{mode: mode, delta: &testDeltaApi{}, reply: &sidecarIdentityReply{SidecarId: &target,
				Status: "active", IdentityAlg: configIdentityAlgEd25519, IdentityPublicKey: verified.IdentityPublicKey, Binding: keys}}
			api.landAdmission = func(signed *bridge.Signed) {
				var admit protocol.SidecarAdmit
				if err := proto.Unmarshal(signed.GetBody(), &admit); err != nil {
					t.Fatal(err)
				}
				digest := bridge.SignedBytesSha256(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_SIDECAR_ADMIT, signed.GetBody())
				authority.stateLock.Lock()
				defer authority.stateLock.Unlock()
				authority.sidecars[target] = &AclSidecar{MemberId: world.memberId, Ephemeral: admit.GetEphemeral(), Row: &bridge.SidecarRow{
					SidecarId: target.Bytes(), MemberId: world.memberId.Bytes(), IdentityPublicKey: verified.IdentityPublicKey,
					Ephemeral: admit.GetEphemeral(), Capabilities: admit.GetCapabilities(), NotAfter: admit.GetNotAfter(),
					AdmissionSigners: [][]byte{identity.SidecarId.Bytes()}, AdmissionSha256: digest[:]}}
			}
			running.sidecarApi.setTransport(api)
			terms := BrowserAdmissionTerms{Mode: mode}
			if mode == BrowserAdmissionBurner {
				terms.MailboxId, terms.NotAfterMs = mailbox, world.clock.Now().Add(time.Hour).UnixMilli()
			}

			if _, err := running.PreviewBrowserAdmission(t.Context(), target, terms); !errors.Is(err, ErrSidecarApprovalAuthority) {
				t.Fatalf("unconsented issuer: %v", err)
			}
			world.consentSelf()
			if _, err := running.PreviewBrowserAdmission(t.Context(), target, terms); !errors.Is(err, ErrSidecarApiReply) {
				t.Fatalf("ordinary identity reply: %v", err)
			}
			api.reply.BrowserAdmission = mode
			preview, err := running.PreviewBrowserAdmission(t.Context(), target, terms)
			if err != nil || preview == nil || preview.SafetyNumber != number || preview.Terms != terms {
				t.Fatalf("preview: %+v %v", preview, err)
			}
			changed := *preview
			changed.SafetyNumber = "different"
			if err := running.ConfirmBrowserAdmission(t.Context(), target, changed, nil); !errors.Is(err, ErrBrowserAdmissionConfirmation) {
				t.Fatalf("changed safety number: %v", err)
			}
			if len(api.delta.postsSoFar()) != 0 {
				t.Fatal("preview signed a statement")
			}
			if mode == BrowserAdmissionBurner {
				api.delta.answers = []string{"ok", "lost"}
			}
			err = running.ConfirmBrowserAdmission(t.Context(), target, *preview, nil)
			if mode == BrowserAdmissionPage && err != nil || mode == BrowserAdmissionBurner && !errors.Is(err, ErrSidecarActPending) {
				t.Fatal(err)
			}
			posts := api.delta.postsSoFar()
			if len(posts) != 2 {
				t.Fatalf("signed %d statements", len(posts))
			}
			decode := func(raw []byte, typ bridge.SignedType, msg proto.Message) {
				t.Helper()
				var signed bridge.Signed
				if err := proto.Unmarshal(raw, &signed); err != nil {
					t.Fatal(err)
				}
				if bridge.SignedType(signed.GetType()) != typ {
					t.Fatalf("statement type: %v", signed.GetType())
				}
				if err := proto.Unmarshal(signed.GetBody(), msg); err != nil {
					t.Fatal(err)
				}
			}
			var admit protocol.SidecarAdmit
			decode(posts[0], bridge.SignedType_SIGNED_SIDECAR_ADMIT, &admit)
			if !bytes.Equal(admit.GetMemberId(), world.memberId.Bytes()) || !bytes.Equal(admit.GetSidecarId(), target.Bytes()) ||
				!bytes.Equal(admit.GetIdentityPublicKey(), verified.IdentityPublicKey) || len(admit.GetTagIds()) != 0 {
				t.Fatalf("admission: %+v", &admit)
			}
			if mode == BrowserAdmissionPage {
				var confirm protocol.OwnerConfirm
				decode(posts[1], bridge.SignedType_SIGNED_OWNER_CONFIRM, &confirm)
				if admit.GetCapabilities() != uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY) || admit.GetEphemeral() || !bytes.Equal(confirm.GetSidecarId(), target.Bytes()) {
					t.Fatalf("page admission: %+v %+v", &admit, &confirm)
				}
				return
			}
			var share protocol.EvsShare
			decode(posts[1], bridge.SignedType_SIGNED_EVS_SHARE, &share)
			if !admit.GetEphemeral() || admit.GetCapabilities() != 0 || admit.GetNotAfter() != terms.NotAfterMs || share.GetExpires() != terms.NotAfterMs ||
				!bytes.Equal(share.GetRepoId(), mailbox.Bytes()) || !bytes.Equal(share.GetSubject(), target.Bytes()) {
				t.Fatalf("burner grant: %+v %+v", &admit, &share)
			}
			// The follower sees the admission while the original grant is awaiting its lost response.
			later := terms
			later.NotAfterMs += time.Minute.Milliseconds()
			preview, err = running.PreviewBrowserAdmission(t.Context(), target, later)
			if err != nil || preview.Terms != terms {
				t.Fatalf("retry widened expiry: %+v %v", preview, err)
			}
			if err := running.ConfirmBrowserAdmission(t.Context(), target, *preview, nil); err != nil {
				t.Fatal(err)
			}
			replayed := api.delta.postsSoFar()
			if len(replayed) != 3 || !bytes.Equal(replayed[2], posts[1]) {
				t.Fatal("retry did not reuse the signed share")
			}
			authority.mailbox.Shares = []*protocol.AclRepoShareRow{{Subject: target.Bytes(), Signer: identity.SidecarId.Bytes(), Expires: terms.NotAfterMs}}
			if err := running.ConfirmBrowserAdmission(t.Context(), target, *preview, nil); err != nil || len(api.delta.postsSoFar()) != 3 {
				t.Fatalf("completed retry: %v", err)
			}
		})
	}
}
