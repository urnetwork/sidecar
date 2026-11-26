// GET /sidecar/label on the fake api (fake_api_label.go): each bearer reads its own network's names, a label drawn at
// the network's first read standing after it and a set one answered with its aliases; the refusals server's route
// answers; and the names a test may set. fake_api_label_daemon_test.go reads them through a world's label refresh.

package sidecartest

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// A fake api over a fake first cluster of its own; nil settings take the defaults.
func newFakeApiLabelTestApi(t *testing.T, settings *FakeApiSettings) *FakeApi {
	t.Helper()
	clock := NewFakeClock(DefaultClockStart())
	faults := NewFaultQueue()
	blobs := NewFakeBlobs(clock, faults, nil, DefaultFakeBlobsSettings())
	cluster, err := blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	return NewFakeApi(t.Context(), clock, faults, nil, cluster, settings)
}

// One GET /sidecar/label on bearer, none for "", through the api's transport: the status, the answer decoded as
// SidecarApi.GetSidecarLabel decodes it on a 200, and the body.
func getFakeApiLabel(t *testing.T, api *FakeApi, bearer string) (int, *sidecar.SidecarLabel, string) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, api.Origin()+"/sidecar/label", nil)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := api.Transport().RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		return response.StatusCode, nil, string(body)
	}
	answer := &sidecar.SidecarLabel{}
	if err := json.Unmarshal(body, answer); err != nil {
		t.Fatalf("the answer does not decode: %v", err)
	}
	return response.StatusCode, answer, string(body)
}

// A bearer of a forwarding client of networkId, as POST /network/auth-client mints a sidecar's forwarding client.
func fakeApiLabelForwardingToken(api *FakeApi, networkId sidecar.Id) string {
	return api.mintClientToken(&fakeApiClient{
		networkId:    networkId,
		clientId:     sidecar.NewId(),
		sidecarId:    sidecar.NewId(),
		deviceId:     sidecar.NewId(),
		sessionId:    sidecar.NewId(),
		strictExp:    true,
		adminRefused: true,
		forwardOnly:  true,
		createTime:   api.clock.Now(),
	})
}

// Each bearer reads its own network's names: a set label with its alias and retiring alias, and for a network named
// nothing a label drawn at its first read, of the drawn form, that every later read answers, its alias and retiring
// aliases left out of the body as server leaves them out while there are none. Any client of the network reads them,
// one bound to no sidecar among them.
func TestFakeApiLabelAnswersTheBearersOwnNetwork(t *testing.T) {
	api := newFakeApiLabelTestApi(t, nil)
	named, drawn := sidecar.NewId(), sidecar.NewId()
	tombstoneTime := DefaultClockStart().Add(90 * 24 * time.Hour).UTC()
	retiring := []sidecar.NetworkLabelRetiringAlias{{Alias: "team-older", TombstoneTime: tombstoneTime}}
	if err := api.SetNetworkLabel(named, &FakeApiNetworkLabel{Label: "a7q2m9x4k1", Alias: "team-alpha", RetiringAliases: retiring}); err != nil {
		t.Fatal(err)
	}
	status, answer, body := getFakeApiLabel(t, api, api.ClientToken(named, sidecar.NewId(), sidecar.NewId()))
	if status != http.StatusOK || answer.NetworkId != named || answer.Label != "a7q2m9x4k1" || answer.Alias != "team-alpha" ||
		len(answer.RetiringAliases) != 1 || answer.RetiringAliases[0].Alias != "team-older" ||
		!answer.RetiringAliases[0].TombstoneTime.Equal(tombstoneTime) {
		t.Fatalf("the named network's read: %d %s", status, body)
	}

	if _, held := api.NetworkLabel(drawn); held {
		t.Fatal("a network no read asked about holds a label")
	}
	status, first, body := getFakeApiLabel(t, api, api.ClientToken(drawn, sidecar.NewId(), sidecar.Id{}))
	if status != http.StatusOK || first.NetworkId != drawn || first.Alias != "" || len(first.RetiringAliases) != 0 {
		t.Fatalf("the unnamed network's first read: %d %s", status, body)
	}
	if len(first.Label) != 10 || sidecar.ValidateDnsName(first.Label) != nil || first.Label == answer.Label {
		t.Fatalf("the drawn label %q", first.Label)
	}
	if strings.Contains(body, "alias") {
		t.Fatalf("a body with no alias names one: %s", body)
	}
	status, second, _ := getFakeApiLabel(t, api, api.ClientToken(drawn, sidecar.NewId(), sidecar.NewId()))
	if status != http.StatusOK || second.Label != first.Label {
		t.Fatalf("a later read of the drawn network: %d %+v, the first drew %q", status, second, first.Label)
	}
	if held, ok := api.NetworkLabel(drawn); !ok || held.Label != first.Label {
		t.Fatalf("the api holds %+v for the drawn network", held)
	}
	if count := api.RouteCount(fakeApiLabelRoute); count != 3 {
		t.Fatalf("the route counted %d reads", count)
	}
}

// The route refuses as server's does: 401 with no bearer or one the api does not know, 403 in the strict_exp gate's
// text to a forwarding client's token, and 503 while labels are unavailable or once LabelDrawCount draws are spent, a
// refused read drawing nothing; a network's set label answers with no draw at all.
func TestFakeApiLabelRefusesAsApiRefuses(t *testing.T) {
	api := newFakeApiLabelTestApi(t, nil)
	networkId := sidecar.NewId()
	for _, bearer := range []string{"", "not-a-token-of-this-api"} {
		if status, _, body := getFakeApiLabel(t, api, bearer); status != http.StatusUnauthorized {
			t.Errorf("bearer %q: %d %s", bearer, status, body)
		}
	}
	if status, _, body := getFakeApiLabel(t, api, fakeApiLabelForwardingToken(api, networkId)); status != http.StatusForbidden || strings.TrimSpace(body) != fakeApiStrictExpRefusedText {
		t.Errorf("a forwarding client's read: %d %s", status, body)
	}
	token := api.ClientToken(networkId, sidecar.NewId(), sidecar.NewId())
	api.SetNetworkLabelsUnavailable(true)
	if status, _, body := getFakeApiLabel(t, api, token); status != http.StatusServiceUnavailable {
		t.Errorf("a read while labels are unavailable: %d %s", status, body)
	}
	if _, held := api.NetworkLabel(networkId); held {
		t.Fatal("a refused read drew a label")
	}
	api.SetNetworkLabelsUnavailable(false)
	if status, answer, body := getFakeApiLabel(t, api, token); status != http.StatusOK || answer.NetworkId != networkId {
		t.Errorf("a read once labels are available again: %d %s", status, body)
	}

	settings := DefaultFakeApiSettings()
	settings.LabelDrawCount = 0
	spent := newFakeApiLabelTestApi(t, settings)
	unnamed, named := sidecar.NewId(), sidecar.NewId()
	if status, _, body := getFakeApiLabel(t, spent, spent.ClientToken(unnamed, sidecar.NewId(), sidecar.NewId())); status != http.StatusServiceUnavailable {
		t.Errorf("a first read with no draw left: %d %s", status, body)
	}
	if _, held := spent.NetworkLabel(unnamed); held {
		t.Fatal("a read with no draw left holds a label")
	}
	if err := spent.SetNetworkLabel(named, &FakeApiNetworkLabel{Label: "b3k8p2r6t0"}); err != nil {
		t.Fatal(err)
	}
	if status, answer, body := getFakeApiLabel(t, spent, spent.ClientToken(named, sidecar.NewId(), sidecar.NewId())); status != http.StatusOK || answer.Label != "b3k8p2r6t0" {
		t.Errorf("a set label with no draw left: %d %s", status, body)
	}
}

// A test names only what api's dns_label could hold: a label, names api could hold, distinct, and none another
// network holds as a label, an alias or a retiring alias, a drawn label among them. A network's label never changes
// once held; its aliases do.
func TestFakeApiSetNetworkLabelHoldsApisNames(t *testing.T) {
	api := newFakeApiLabelTestApi(t, nil)
	alpha, bravo, charlie := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	if err := api.SetNetworkLabel(alpha, &FakeApiNetworkLabel{Label: "a7q2m9x4k1", Alias: "team-alpha"}); err != nil {
		t.Fatal(err)
	}
	reserved := ""
	for _, label := range sidecar.ReservedDnsLabels() {
		if 5 <= len(label) && !strings.Contains(label, "-") {
			reserved = label
			break
		}
	}
	if reserved == "" {
		t.Fatal("no reserved label of five letters to name")
	}
	refused := map[string]*FakeApiNetworkLabel{
		"no label":                          {Alias: "team-bravo"},
		"an uppercase label":                {Label: "B3K8P2R6T0"},
		"a reserved label":                  {Label: reserved},
		"a short alias":                     {Label: "b3k8p2r6t0", Alias: "abc"},
		"alpha's label as an alias":         {Label: "b3k8p2r6t0", Alias: "a7q2m9x4k1"},
		"alpha's alias as a label":          {Label: "team-alpha"},
		"alpha's alias as a retiring alias": {Label: "b3k8p2r6t0", RetiringAliases: []sidecar.NetworkLabelRetiringAlias{{Alias: "team-alpha"}}},
		"its own label as its alias":        {Label: "b3k8p2r6t0", Alias: "b3k8p2r6t0"},
	}
	for name, label := range refused {
		if err := api.SetNetworkLabel(bravo, label); err == nil {
			t.Errorf("%s was taken", name)
		}
	}
	if _, held := api.NetworkLabel(bravo); held {
		t.Fatal("a refused name stuck")
	}

	if err := api.SetNetworkLabel(alpha, &FakeApiNetworkLabel{Label: "c5n1w7d3y9"}); err == nil {
		t.Fatal("a network's label changed")
	}
	changed := &FakeApiNetworkLabel{Label: "a7q2m9x4k1", Alias: "team-alpha-next", RetiringAliases: []sidecar.NetworkLabelRetiringAlias{{Alias: "team-alpha"}}}
	if err := api.SetNetworkLabel(alpha, changed); err != nil {
		t.Fatalf("an alias change: %v", err)
	}
	if held, _ := api.NetworkLabel(alpha); held.Alias != "team-alpha-next" || len(held.RetiringAliases) != 1 {
		t.Fatalf("alpha holds %+v", held)
	}

	_, drawn, body := getFakeApiLabel(t, api, api.ClientToken(bravo, sidecar.NewId(), sidecar.NewId()))
	if drawn == nil {
		t.Fatalf("bravo's first read: %s", body)
	}
	if err := api.SetNetworkLabel(charlie, &FakeApiNetworkLabel{Label: drawn.Label}); err == nil {
		t.Fatal("another network took a drawn label")
	}
	if err := api.SetNetworkLabel(bravo, &FakeApiNetworkLabel{Label: drawn.Label, Alias: "team-bravo"}); err != nil {
		t.Fatalf("an alias beside a drawn label: %v", err)
	}
}
