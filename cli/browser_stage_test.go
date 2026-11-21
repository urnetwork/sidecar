//go:build pagestack_member && !js && !sidecar_http && !ios_extension

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
)

// Playwright stages the real key-origin Worker. This companion serves only on loopback.
// It holds the fixture owner's signing key. The browser enrolls with its own key.
func TestStagedBrowserMemberServices(t *testing.T) {
	ready := os.Getenv("PAGESTACK_MEMBER_READY")
	if ready == "" {
		t.Skip("started by the signed browser fixture")
	}
	port, err := strconv.Atoi(os.Getenv("PAGESTACK_PORT"))
	if err != nil || port < 1 || port > 65535 {
		t.Fatal("invalid staged fixture port")
	}
	ctx := t.Context()
	netSettings := sidecartest.DefaultNetSettings()
	netSettings.ClockStart = time.Now()
	domain := "sidecartest.example:" + strconv.Itoa(port)
	netSettings.Api = sidecartest.DefaultFakeApiSettings()
	netSettings.Api.Origin, netSettings.Api.AuthOrigin = "https://api."+domain, "https://auth."+domain
	netSettings.Api.ServiceDomain = domain
	world := sidecartest.NewNet(ctx, netSettings)
	t.Cleanup(world.Close)
	api, err := world.Api()
	if err != nil {
		t.Fatal(err)
	}
	engineSettings := enginenet.DefaultEnginesSettings()
	engineSettings.FollowBeforeExchange = true
	engines := enginenet.NewEngines(t, world, engineSettings)
	network, member := sidecar.NewId(), sidecar.NewId()
	api.SetPersonalOwner(network, member)
	// A read-only vault reader must land its signed read receipt before decrypting.
	// FakeQuota's empty tier has zero receipts; provision the ordinary daily allowance.
	world.Fakes().Quota.SetLimits(connect.Id(network), &sidecar.QuotaLimits{
		Tier: "pro", Limits: map[string]int64{"evs_read_receipts_per_repo_day": 256},
	})
	host, err := world.StartInstance("staged browser approver", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(host.Close)
	owner, err := host.AddSidecarIn(network, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := urDaemonGkmClient(owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engines.Bootstrap(ctx, &enginenet.BootstrapArgs{Sidecar: owner, Gkm: keys, OwnerMemberId: member}, nil); err != nil {
		t.Fatal(err)
	}
	follower := startUrConfigFollower(owner, sidecar.NewNoopLogger())
	if follower == nil {
		t.Fatal("owner has no follower")
	}
	config, err := follower.WaitStanding(ctx)
	if err != nil {
		t.Fatal(err)
	}
	vault, err := engines.CreateRepo(ctx, &enginenet.CreateRepoArgs{Sidecar: owner, Gkm: keys, Kind: protocol.RepoKind_REPO_KIND_VAULT, OwnerMemberId: &member})
	if err != nil {
		t.Fatal(err)
	}
	evs, err := urDaemonEvsClient(owner)
	if err != nil {
		t.Fatal(err)
	}
	record, err := owner.Record()
	if err != nil {
		t.Fatal(err)
	}
	if err := record.BindMemberReplica(config, evs); err != nil {
		t.Fatal(err)
	}
	if err := record.PrepareDirectWrites(ctx); err != nil {
		t.Fatal(err)
	}
	note := "The first signed note in this browser fixture."
	refs, err := record.Writer().Append(&sidecar.RecordDraft{Kind: sidecar.RecordKindNote, Source: sidecar.RecordSourceAgent, NoSession: true, Body: &protocol.CoordinationBody{Text: note}})
	if err != nil || len(refs) != 1 || refs[0].Spooled || refs[0].LogId != vault {
		t.Fatalf("fixture note did not enter the vault: %v", err)
	}
	if err := record.Land(ctx, refs); err != nil {
		t.Fatal(err)
	}
	// Once a directory exists, coordination notes route there. This note belongs to the owner's vault.
	directory, err := engines.CreateRepo(ctx, &enginenet.CreateRepoArgs{Sidecar: owner, Gkm: keys, Kind: protocol.RepoKind_REPO_KIND_DIRECTORY})
	if err != nil {
		t.Fatal(err)
	}
	if err := record.PrepareDirectWrites(ctx); err != nil {
		t.Fatal(err)
	}
	dirClient, err := owner.DirectoryClient()
	if err != nil {
		t.Fatal(err)
	}
	cards, err := sidecar.NewDirectoryEvsCards(&sidecar.DirectoryEvsCardsArgs{Client: evs})
	if err != nil {
		t.Fatal(err)
	}
	dirClient.Bind(cards, func() sidecar.DirectoryAuthView { return sidecar.NewDirectoryAuthView(config.State()) })
	const description = "Shared test description"
	announcement, err := dirClient.AnnounceRepo(ctx, &sidecar.DirectoryRepoAnnounceArgs{RepoId: vault, Description: description})
	if err != nil || announcement == nil || announcement.Entry == nil || announcement.Entry.LogId != directory {
		t.Fatalf("fixture directory announcement: %v", err)
	}
	if err := record.Land(ctx, []*sidecar.RecordEntryRef{announcement.Entry}); err != nil {
		t.Fatal(err)
	}

	identity := owner.Identity()
	world.Fakes().Push.BindSidecar(connect.Id(identity.SidecarId), connect.Id(identity.ClientId))
	push, err := world.HintWriter()
	if err != nil {
		t.Fatal(err)
	}
	_, hints, err := testUrClientsOf(owner).intake()
	if err != nil {
		t.Fatal(err)
	}
	// Deliver the service's own notices to the subscribed stock writer. ReaderWraps are created by
	// its ordinary handler after the new browser publishes a ReaderKey and asks for a missing wrap.
	poll, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		read := 0
		for {
			select {
			case <-poll.Done():
				return
			case now := <-tick.C:
				if world.Clock().Now().Before(now) {
					world.Clock().AdvanceTo(now)
				}
				items := world.Fakes().Push.AllHints()
				for ; read < len(items); read++ {
					item := items[read]
					h := item.Hint
					if item.ClientId == connect.Id(identity.ClientId) {
						if h.Topic == sidecar.PushTopicGkm || strings.HasPrefix(h.Topic, sidecar.PushTopicGkmGroupPrefix) {
							hints.Receive(sidecar.PushNotice{Topic: h.Topic, Version: h.Version, Kind: h.Kind, Hint: h.Body})
						}
					} else if _, err := push.HintClient(poll, item.ClientId, h); err != nil && poll.Err() == nil {
						t.Errorf("forward service hint to poll: %v", err)
						return
					}
				}
			}
		}
	}()
	t.Cleanup(func() { stop(); <-done })

	code := sidecar.NewId().String()
	sessionClaims, _ := json.Marshal(map[string]any{"network_id": network, "exp": time.Now().Add(time.Hour).Unix(), "nonce": sidecar.NewId()})
	session := "eyJhbGciOiJIUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(sessionClaims) + "." + base64.RawURLEncoding.EncodeToString(sidecar.NewId().Bytes())
	var lock sync.Mutex
	var codeUsed bool
	var browserClient sidecar.Id
	finish := make(chan struct{})
	var finishOnce sync.Once
	reply := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/finish" {
			finishOnce.Do(func() { close(finish) })
			return
		}
		if r.Method == "POST" && r.URL.Path == "/approve" {
			var p struct {
				SidecarID sidecar.Id
				Safety    string
			}
			if json.NewDecoder(r.Body).Decode(&p) != nil {
				w.WriteHeader(400)
				return
			}
			preview, err := owner.PreviewBrowserAdmission(r.Context(), p.SidecarID, sidecar.BrowserAdmissionTerms{Mode: sidecar.BrowserAdmissionPage})
			if err != nil || sidecar.FormatSafetyNumber(preview.SafetyNumber) != p.Safety {
				w.WriteHeader(403)
				return
			}
			lock.Lock()
			clientId := browserClient
			lock.Unlock()
			world.Fakes().Push.BindSidecar(connect.Id(p.SidecarID), connect.Id(clientId))
			if err = owner.ConfirmBrowserAdmission(r.Context(), p.SidecarID, *preview, nil); err != nil {
				t.Logf("owner confirmation: %v", err)
				w.WriteHeader(503)
				return
			}
			if err = engines.Sync(r.Context(), network); err != nil {
				t.Logf("gate sync: %v", err)
				w.WriteHeader(503)
				return
			}
			// FakeApi stores the real signed entries. Notify both replicas of the
			// API's tip, including OwnerConfirm, as the team publisher does.
			tip, err := api.Tip(r.Context(), network)
			if err != nil || tip == nil {
				w.WriteHeader(503)
				return
			}
			config.ReceiveNotice(sidecar.PushNotice{Topic: sidecar.PushTopicTeam, Version: tip.GetVersion()})
			if _, err := push.HintClient(r.Context(), connect.Id(clientId), &sidecar.ClientHint{
				Topic: sidecar.PushTopicTeam, Version: tip.GetVersion(),
			}); err != nil {
				t.Logf("team hint: %v", err)
				w.WriteHeader(503)
				return
			}
			state, err := config.WaitFor(r.Context(), tip.GetVersion())
			if err != nil || state.SidecarRow(p.SidecarID).GetOwnerConfirmedAt() == 0 ||
				!slices.Contains(state.RepoReadersAt(vault, world.Clock().Now()), p.SidecarID) {
				t.Logf("writer has no verified browser consent for the fixture vault: %v", err)
				w.WriteHeader(503)
				return
			}
			reply(w, map[string]bool{"approved": true})
			return
		}
		service, path, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/service/"), "/")
		if !ok || !strings.HasPrefix(r.URL.Path, "/service/") || (service != "api" && service != "auth" && service != "evs" && service != "gkm") {
			http.NotFound(w, r)
			return
		}
		if service == "api" && r.Method == "POST" && path == "auth/code-login" {
			var p struct {
				Code string `json:"auth_code"`
			}
			lock.Lock()
			defer lock.Unlock()
			if json.NewDecoder(r.Body).Decode(&p) != nil || p.Code != code || codeUsed {
				w.WriteHeader(403)
				return
			}
			codeUsed = true
			reply(w, map[string]string{"by_jwt": session})
			return
		}
		if service == "api" && r.Method == "POST" && path == "network/auth-client" && r.Header.Get("Authorization") == "Bearer "+session {
			var p struct {
				NoEgress  bool `json:"declares_no_egress"`
				Admin     bool `json:"admin_refused"`
				Strict    bool `json:"strict_exp"`
				Ephemeral bool `json:"ephemeral"`
			}
			lock.Lock()
			defer lock.Unlock()
			if !codeUsed || browserClient != (sidecar.Id{}) || json.NewDecoder(r.Body).Decode(&p) != nil || !p.NoEgress || !p.Admin || !p.Strict || p.Ephemeral {
				w.WriteHeader(403)
				return
			}
			id, token, ok := api.NewPageClient(network, member, identity.ClientId)
			if !ok {
				w.WriteHeader(403)
				return
			}
			browserClient = id
			reply(w, map[string]any{"by_client_jwt": token, "client_id": id, "admin_refused": true, "strict_exp": true, "declares_no_egress": true})
			return
		}
		request := r.Clone(r.Context())
		request.URL.Scheme = "https"
		request.URL.Host = service + "." + domain
		request.Host = request.URL.Host
		request.URL.Path = "/" + path
		request.URL.RawPath = ""
		request.RequestURI = ""
		res, err := api.Transport().RoundTrip(request)
		if err != nil {
			w.WriteHeader(503)
			return
		}
		defer res.Body.Close()
		for name, values := range res.Header {
			for _, val := range values {
				w.Header().Add(name, val)
			}
		}
		w.WriteHeader(res.StatusCode)
		_, _ = io.Copy(w, res.Body)
	}))
	t.Cleanup(func() {
		server.CloseClientConnections()
		server.Close()
	})
	info, err := json.Marshal(map[string]string{
		"backend": server.URL, "network": network.String(), "member": member.String(), "vault": vault.String(),
		"directory": directory.String(), "description": description, "entry": refs[0].EntryId.String(), "note": note, "code": code,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(ready+".tmp", info, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(ready+".tmp", ready); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
		t.Fatalf("fixture canceled: %v", ctx.Err())
	case <-finish:
	}
}
