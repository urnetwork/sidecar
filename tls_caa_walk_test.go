//go:build !ios_extension

// RFC 8659 §3's walk on a scripted resolver: its two worked examples, an alias followed without climbing from its
// target, and §12.8's refusal of every way a walk can meet a URnetwork zone. Every name is under .example, and
// root.example stands for <root>.

package sidecar

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// The operator zone the tests refuse, standing for <root>.
const testCaaOperatorZone = "root.example"

// A resolver that answers from a table, logging every query, and fails the names in failures.
type testCaaResolver struct {
	answers  map[string]*TlsCaaAnswer
	failures map[string]error
	queried  []string
}

func (self *testCaaResolver) LookupCaa(ctx context.Context, name string) (*TlsCaaAnswer, error) {
	self.queried = append(self.queried, name)
	if err := self.failures[name]; err != nil {
		return nil, err
	}
	if answer, ok := self.answers[name]; ok {
		return answer, nil
	}
	// NODATA at a name in its own zone, under one provider's servers
	return testCaaAnswer(name, testCaaZoneOf(name)), nil
}

// The zone a test name sits in: its last two labels, or the name itself when it has fewer.
func testCaaZoneOf(name string) string {
	labels := 0
	for index := len(name) - 1; 0 <= index; index -= 1 {
		if name[index] == '.' {
			labels += 1
			if labels == 2 {
				return name[index+1:]
			}
		}
	}
	return name
}

// An answer for name in zone, served by the customer's provider, holding records.
func testCaaAnswer(name string, zone string, records ...string) *TlsCaaAnswer {
	return &TlsCaaAnswer{
		Hops:    []*TlsCaaHop{{Name: name, Zone: zone, Nameservers: []string{"ns1.provider.example", "ns2.provider.example"}}},
		Records: records,
	}
}

func TestTlsCaaWalkClimbsToTheRootWithNoSet(t *testing.T) {
	// RFC 8659 §3: CAA("X.Y.Z.") = Empty, CAA("Y.Z.") = Empty, CAA("Z.") = Empty, return Empty
	resolver := &testCaaResolver{}
	result, err := TlsCaaWalk(context.Background(), resolver, "X.Y.Z", []string{testCaaOperatorZone}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"x.y.z", "y.z", "z"}; !slices.Equal(resolver.queried, want) {
		t.Errorf("queried %v, want %v", resolver.queried, want)
	}
	if len(result.Effective) != 0 || result.EffectiveOwner != "" || len(result.Steps) != 3 {
		t.Errorf("effective %v at %q after %d steps", result.Effective, result.EffectiveOwner, len(result.Steps))
	}
}

func TestTlsCaaWalkStopsAtTheFirstSet(t *testing.T) {
	// RFC 8659 §3: CAA("A.B.C.") = Empty, CAA("B.C.") = "issue example.com", return "issue example.com"
	resolver := &testCaaResolver{answers: map[string]*TlsCaaAnswer{
		"b.c": testCaaAnswer("b.c", "b.c", `0 issue "example.com"`),
		"c":   testCaaAnswer("c", "c", `0 issue "never.example"`),
	}}
	result, err := TlsCaaWalk(context.Background(), resolver, "A.B.C.", []string{testCaaOperatorZone}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a.b.c", "b.c"}; !slices.Equal(resolver.queried, want) {
		t.Errorf("queried %v, want %v", resolver.queried, want)
	}
	if !slices.Equal(result.Effective, []string{`0 issue "example.com"`}) || result.EffectiveOwner != "b.c" {
		t.Errorf("effective %v at %q", result.Effective, result.EffectiveOwner)
	}
}

func TestTlsCaaWalkFollowsAnAliasToItsSet(t *testing.T) {
	pin := `0 issue "ca.example; accounturi=https://ca.example/acct/1"`
	resolver := &testCaaResolver{answers: map[string]*TlsCaaAnswer{
		"app.customer.example": {
			Hops: []*TlsCaaHop{
				{Name: "app.customer.example", Zone: "customer.example", Nameservers: []string{"ns1.provider.example"}},
				{Name: "edge.cdn.example", Zone: "cdn.example", Nameservers: []string{"ns1.cdn-dns.example"}},
			},
			Records: []string{pin},
		},
	}}
	result, err := TlsCaaWalk(context.Background(), resolver, "app.customer.example", []string{testCaaOperatorZone}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(result.Effective, []string{pin}) || result.EffectiveOwner != "edge.cdn.example" {
		t.Errorf("effective %v at %q", result.Effective, result.EffectiveOwner)
	}
	zoneNames := []string{}
	for _, zone := range result.Zones {
		zoneNames = append(zoneNames, zone.Name)
	}
	if !slices.Equal(zoneNames, []string{"customer.example", "cdn.example"}) {
		t.Errorf("zones %v", zoneNames)
	}
}

func TestTlsCaaWalkClimbsFromTheQueriedNameNotTheTarget(t *testing.T) {
	// the alias's target has no set, and its parent has one the walk must never read
	pin := `0 issue "ca.example; accounturi=https://ca.example/acct/1"`
	resolver := &testCaaResolver{answers: map[string]*TlsCaaAnswer{
		"app.customer.example": {
			Hops: []*TlsCaaHop{
				{Name: "app.customer.example", Zone: "customer.example", Nameservers: []string{"ns1.provider.example"}},
				{Name: "edge.cdn.example", Zone: "cdn.example", Nameservers: []string{"ns1.cdn-dns.example"}},
			},
		},
		"customer.example": testCaaAnswer("customer.example", "customer.example", pin),
		"cdn.example":      testCaaAnswer("cdn.example", "cdn.example", `0 issue "other-ca.example"`),
	}}
	result, err := TlsCaaWalk(context.Background(), resolver, "app.customer.example", []string{testCaaOperatorZone}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"app.customer.example", "customer.example"}; !slices.Equal(resolver.queried, want) {
		t.Errorf("queried %v, want %v", resolver.queried, want)
	}
	if !slices.Equal(result.Effective, []string{pin}) || result.EffectiveOwner != "customer.example" {
		t.Errorf("effective %v at %q", result.Effective, result.EffectiveOwner)
	}
	// the probe repeats every name the walk reached, the target's included, each once
	queryNames := []string{}
	for _, query := range result.Queries() {
		queryNames = append(queryNames, query.Name)
	}
	if want := []string{"app.customer.example", "edge.cdn.example", "customer.example"}; !slices.Equal(queryNames, want) {
		t.Errorf("queries %v, want %v", queryNames, want)
	}
}

func TestTlsCaaWalkRefusesAnAliasIntoAnOperatorZone(t *testing.T) {
	// FS-32: the customer's pin at the domain, and the host a CNAME to an empty target under <root>, which an
	// operator CAA at the exact target would govern
	pin := `0 issue "ca.example; accounturi=https://ca.example/acct/1"`
	for _, records := range [][]string{nil, {`0 issue "ca.example; accounturi=https://ca.example/acct/operator"`}} {
		resolver := &testCaaResolver{answers: map[string]*TlsCaaAnswer{
			"app.customer.example": {
				Hops: []*TlsCaaHop{
					{Name: "app.customer.example", Zone: "customer.example", Nameservers: []string{"ns1.provider.example"}},
					{Name: "web.net1.root.example", Zone: "net1.root.example", Nameservers: []string{"ns1.dns.example"}},
				},
				Records: records,
			},
			"customer.example": testCaaAnswer("customer.example", "customer.example", pin),
		}}
		result, err := TlsCaaWalk(context.Background(), resolver, "app.customer.example", []string{testCaaOperatorZone}, nil)
		if !errors.Is(err, ErrTlsCaaOperatorAlias) || result.OperatorName != "web.net1.root.example" {
			t.Fatalf("records %v: %v at %q", records, err, result.OperatorName)
		}
		if len(result.Effective) != 0 {
			t.Errorf("a refused walk reports a set: %v", result.Effective)
		}
		if slices.Contains(resolver.queried, "customer.example") {
			t.Errorf("the walk climbed past a refusal: %v", resolver.queried)
		}
	}
}

func TestTlsCaaWalkRefusesAWildcardAliasIntoAnOperatorZone(t *testing.T) {
	// *.customer.example CNAME web.net1.root.example answers for app.customer.example as for any name under it
	resolver := &testCaaResolver{answers: map[string]*TlsCaaAnswer{
		"app.customer.example": {
			Hops: []*TlsCaaHop{
				{Name: "app.customer.example", Zone: "customer.example", Nameservers: []string{"ns1.provider.example"}},
				{Name: "web.net1.root.example", Zone: "root.example", Nameservers: []string{"ns1.dns.example"}},
			},
		},
	}}
	_, err := TlsCaaWalk(context.Background(), resolver, "app.customer.example", []string{testCaaOperatorZone}, nil)
	if !errors.Is(err, ErrTlsCaaOperatorAlias) {
		t.Fatal(err)
	}
}

func TestTlsCaaWalkRefusesAZoneOnOperatorServers(t *testing.T) {
	// the host delegated to URnetwork's nameservers: its CAA is whatever they answer
	resolver := &testCaaResolver{answers: map[string]*TlsCaaAnswer{
		"app.customer.example": {
			Hops: []*TlsCaaHop{
				{Name: "app.customer.example", Zone: "app.customer.example", Nameservers: []string{"ns1.provider.example", "ns2.root.example"}},
			},
		},
	}}
	result, err := TlsCaaWalk(context.Background(), resolver, "app.customer.example", []string{testCaaOperatorZone}, nil)
	if !errors.Is(err, ErrTlsCaaOperatorAlias) || result.OperatorName != "ns2.root.example" {
		t.Fatalf("%v at %q", err, result.OperatorName)
	}
}

func TestTlsCaaWalkPassesADelegatedChallenge(t *testing.T) {
	// QD-175's one-time _acme-challenge CNAME into <token>.acme.<root> is no name the walk for the host reaches
	pin := `0 issue "ca.example; accounturi=https://ca.example/acct/1"`
	resolver := &testCaaResolver{answers: map[string]*TlsCaaAnswer{
		"_acme-challenge.app.customer.example": {
			Hops: []*TlsCaaHop{
				{Name: "_acme-challenge.app.customer.example", Zone: "customer.example", Nameservers: []string{"ns1.provider.example"}},
				{Name: "token1.acme.root.example", Zone: "root.example", Nameservers: []string{"ns1.dns.example"}},
			},
		},
		"customer.example": testCaaAnswer("customer.example", "customer.example", pin),
	}}
	result, err := TlsCaaWalk(context.Background(), resolver, "app.customer.example", []string{testCaaOperatorZone}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(result.Effective, []string{pin}) || slices.Contains(resolver.queried, "_acme-challenge.app.customer.example") {
		t.Errorf("effective %v after %v", result.Effective, resolver.queried)
	}
}

func TestTlsCaaWalkRefusesAnOperatorNameBeforeAnyQuery(t *testing.T) {
	resolver := &testCaaResolver{}
	result, err := TlsCaaWalk(context.Background(), resolver, "web.net1.root.example", []string{"ROOT.example."}, nil)
	if !errors.Is(err, ErrTlsCaaOperatorAlias) || result.OperatorName != "web.net1.root.example" || len(resolver.queried) != 0 {
		t.Fatalf("%v at %q after %v", err, result.OperatorName, resolver.queried)
	}
}

func TestTlsCaaWalkEndsOnAFailedLookup(t *testing.T) {
	failure := errors.New("servfail")
	resolver := &testCaaResolver{failures: map[string]error{"customer.example": failure}}
	_, err := TlsCaaWalk(context.Background(), resolver, "app.customer.example", []string{testCaaOperatorZone}, nil)
	if !errors.Is(err, failure) {
		t.Fatalf("a failed lookup read as %v", err)
	}
	// an unread parent is never passed over: the walk stops where the lookup failed
	if slices.Contains(resolver.queried, "example") {
		t.Errorf("queried %v", resolver.queried)
	}
}

func TestTlsCaaWalkRefusesAnAnswerItCannotRead(t *testing.T) {
	settings := DefaultTlsCaaWalkSettings()
	settings.HopMaxCount = 2
	longChain := &TlsCaaAnswer{Hops: []*TlsCaaHop{
		{Name: "app.customer.example", Zone: "customer.example", Nameservers: []string{"ns1.provider.example"}},
		{Name: "a.cdn.example", Zone: "cdn.example", Nameservers: []string{"ns1.provider.example"}},
		{Name: "b.cdn.example", Zone: "cdn.example", Nameservers: []string{"ns1.provider.example"}},
	}}
	for _, answer := range []*TlsCaaAnswer{
		// another name than the one queried
		testCaaAnswer("www.customer.example", "customer.example"),
		// a name outside its zone
		testCaaAnswer("app.customer.example", "other.example"),
		// no servers for the probe to ask
		{Hops: []*TlsCaaHop{{Name: "app.customer.example", Zone: "customer.example"}}},
		// a record that is no CAA RDATA
		testCaaAnswer("app.customer.example", "customer.example", "issue ca.example"),
		longChain,
		{},
	} {
		resolver := &testCaaResolver{answers: map[string]*TlsCaaAnswer{"app.customer.example": answer}}
		_, err := TlsCaaWalk(context.Background(), resolver, "app.customer.example", []string{testCaaOperatorZone}, settings)
		if !errors.Is(err, ErrTlsCaaWalk) {
			t.Errorf("an unreadable answer read as %v", err)
		}
	}
	// and a walk with nothing to refuse, or no name, is no walk
	for _, operatorZones := range [][]string{nil, {""}} {
		if _, err := TlsCaaWalk(context.Background(), &testCaaResolver{}, "app.customer.example", operatorZones, nil); !errors.Is(err, ErrTlsCaaWalk) {
			t.Errorf("operator zones %v: %v", operatorZones, err)
		}
	}
	if _, err := TlsCaaWalk(context.Background(), &testCaaResolver{}, "a..example", []string{testCaaOperatorZone}, nil); !errors.Is(err, ErrTlsCaaWalk) {
		t.Errorf("an empty label: %v", err)
	}
}

func TestTlsCaaRecordReadsPresentationForm(t *testing.T) {
	cases := []struct {
		text  string
		want  TlsCaaRecord
		valid bool
	}{
		{text: `0 issue "letsencrypt.org; accounturi=https://acme.example/acct/1"`, want: TlsCaaRecord{Flags: 0, Tag: "issue", Value: "letsencrypt.org; accounturi=https://acme.example/acct/1"}, valid: true},
		{text: `128 tbs "Unknown"`, want: TlsCaaRecord{Flags: 128, Tag: "tbs", Value: "Unknown"}, valid: true},
		{text: `0 iodef "mailto:security@customer.example"`, want: TlsCaaRecord{Flags: 0, Tag: "iodef", Value: "mailto:security@customer.example"}, valid: true},
		{text: `0 issue ca.example`, want: TlsCaaRecord{Flags: 0, Tag: "issue", Value: "ca.example"}, valid: true},
		{text: `0 issue ";"`, want: TlsCaaRecord{Flags: 0, Tag: "issue", Value: ";"}, valid: true},
		{text: `0 issue "a\"b\\c\059d"`, want: TlsCaaRecord{Flags: 0, Tag: "issue", Value: `a"b\c;d`}, valid: true},
		{text: `0 urcanary "00112233445566778899aabbccddeeff"`, want: TlsCaaRecord{Flags: 0, Tag: "urcanary", Value: "00112233445566778899aabbccddeeff"}, valid: true},
		{text: `256 issue "ca.example"`},
		{text: `0 is-sue "ca.example"`},
		{text: `0 issue "ca.example`},
		{text: `0 issue "ca.example" trailing`},
		{text: `0 issue`},
		{text: `issue "ca.example"`},
		{text: `0 issue "\25"`},
	}
	for _, c := range cases {
		record, err := ParseTlsCaaRecord(c.text)
		if !c.valid {
			if err == nil {
				t.Errorf("%q read as %+v", c.text, record)
			}
			continue
		}
		if err != nil || *record != c.want {
			t.Errorf("%q: %+v, %v", c.text, record, err)
			continue
		}
		// what String writes reads back as the same property
		again, err := ParseTlsCaaRecord(record.String())
		if err != nil || *again != *record {
			t.Errorf("%q wrote %q, read back as %+v, %v", c.text, record.String(), again, err)
		}
	}
	if text := (&TlsCaaRecord{Flags: 0, Tag: "issue", Value: "a\nb"}).String(); text != `0 issue "a\010b"` {
		t.Errorf("a control byte wrote %q", text)
	}
}

func TestTlsCaaResultAuthorizesByIssuerAndAccount(t *testing.T) {
	account := "https://ca.example/acme/acct/1234"
	cases := []struct {
		effective  []string
		issuer     string
		accountUri string
		want       bool
	}{
		// RFC 8657 §3's pin: only that account at that CA
		{effective: []string{`0 issue "ca.example; accounturi=https://ca.example/acme/acct/1234"`}, issuer: "ca.example", accountUri: account, want: true},
		{effective: []string{`0 issue "ca.example; accounturi=https://ca.example/acme/acct/1234"`}, issuer: "ca.example", accountUri: "https://ca.example/acme/acct/9", want: false},
		{effective: []string{`0 issue "ca.example; accounturi=https://ca.example/acme/acct/1234"`}, issuer: "other-ca.example", accountUri: account, want: false},
		// a CA with no pin admits every account at it
		{effective: []string{`0 issue "CA.example"`}, issuer: "ca.example", accountUri: "https://ca.example/acme/acct/9", want: true},
		// RFC 8659 §4.2: an issue naming no issuer admits no CA
		{effective: []string{`0 issue ";"`}, issuer: "ca.example", accountUri: account, want: false},
		// no issue property: every CA may issue for a name that is no wildcard
		{effective: []string{`0 issuewild ";"`, `0 iodef "mailto:security@customer.example"`}, issuer: "ca.example", accountUri: account, want: true},
		{effective: nil, issuer: "ca.example", accountUri: account, want: true},
		// a critical property this reader does not know blocks issuance
		{effective: []string{`0 issue "ca.example"`, `128 tbs "Unknown"`}, issuer: "ca.example", accountUri: account, want: false},
		// §12.8's canary is non-critical, so the pin beside it still decides
		{effective: []string{`0 issue "ca.example; accounturi=https://ca.example/acme/acct/1234"`, `0 urcanary "00112233445566778899aabbccddeeff"`}, issuer: "ca.example", accountUri: account, want: true},
		// a value the grammar refuses admits nothing
		{effective: []string{`0 issue "ca.example; accounturi"`}, issuer: "ca.example", accountUri: account, want: false},
	}
	for _, c := range cases {
		result := &TlsCaaResult{Effective: c.effective}
		if got := result.AuthorizesAccount(c.issuer, c.accountUri); got != c.want {
			t.Errorf("%v for %s %s: %v, want %v", c.effective, c.issuer, c.accountUri, got, c.want)
		}
	}
}

func TestTlsCaaResultHoldsCanary(t *testing.T) {
	pinned := &TlsCaaResult{Effective: []string{`0 issue "ca.example; accounturi=https://ca.example/acme/acct/1234"`}}
	flattened := &TlsCaaResult{Effective: []string{
		`0 issue "ca.example; accounturi=https://ca.example/acme/acct/1234"`,
		`0 URCANARY "00112233445566778899aabbccddeeff"`,
	}}
	if pinned.HoldsCanary() || !flattened.HoldsCanary() {
		t.Errorf("pinned %v, flattened %v", pinned.HoldsCanary(), flattened.HoldsCanary())
	}
}
