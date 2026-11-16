//go:build !ios_extension

// Holds a network's standing to operator-core's values on every leg that decodes it (QD-856): its own
// on every leg but sidecar_http, aliased, and api_abuse_standing_http.go's on that one, which the page
// Worker's run reads (TestHttpLegPassesInAWorker names the test). The strings were read off
// operator-core's, and are server's model.AbuseStanding's.

package sidecar

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestAbuseStandingTwinHoldsOperatorCoresValues(t *testing.T) {
	if kind := reflect.TypeFor[AbuseStanding]().Kind(); kind != reflect.String {
		t.Fatalf("AbuseStanding is a %s", kind)
	}
	for _, c := range []struct {
		standing AbuseStanding
		want     string
	}{
		{standing: AbuseStandingProbation, want: "probation"},
		{standing: AbuseStandingStandard, want: "standard"},
		{standing: AbuseStandingTrusted, want: "trusted"},
		{standing: AbuseStandingRestricted, want: "restricted"},
		{standing: AbuseStandingSuspended, want: "suspended"},
	} {
		if string(c.standing) != c.want {
			t.Errorf("standing %q, want %q", c.standing, c.want)
		}
		if !c.standing.Known() {
			t.Errorf("%q is not known", c.standing)
		}
		encoded, err := json.Marshal(AbuseStatus{Standing: c.standing})
		if err != nil {
			t.Fatal(err)
		}
		want := `{"standing":"` + c.want + `","verified":false,"actions":[]}`
		if string(encoded) != want {
			t.Errorf("status %s, want %s", encoded, want)
		}
		var decoded AbuseStatus
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Standing != c.standing {
			t.Errorf("%s decoded to %q", encoded, decoded.Standing)
		}
	}
	// one this build does not know is refused by whoever reads it, on every leg
	for _, standing := range []AbuseStanding{"", "Standard", "standard ", "cleared"} {
		if standing.Known() {
			t.Errorf("%q is known", standing)
		}
	}
}
