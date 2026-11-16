// The issued values (SMTP-M9-10): testdata/smtp/x-ur-ref's vectors, computed apart from this code, fix
// X-UR-Ref's bytes; §22.5's X-UR-Ref MAC refuses a replay under another network's id; Feedback-ID has
// plan-SMTP-small-readings#4's widths, and burners share their network's token.

package smtpedgeservice

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

type xUrRefVector struct {
	KeyId     uint8  `json:"key_id"`
	Key       string `json:"key"`
	SendId    string `json:"send_id"`
	NetworkId string `json:"network_id"`
	Day       uint32 `json:"day"`
	XUrRef    string `json:"x_ur_ref"`
}

type xUrRefRefusal struct {
	XUrRef    string `json:"x_ur_ref"`
	NetworkId string `json:"network_id"`
	Day       uint32 `json:"day"`
	Why       string `json:"why"`
}

type xUrRefVectors struct {
	Vectors  []*xUrRefVector  `json:"vectors"`
	Refusals []*xUrRefRefusal `json:"refusals"`
}

func readXUrRefVectors(t *testing.T) *xUrRefVectors {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "smtp", "x-ur-ref", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	vectors := &xUrRefVectors{}
	if err := json.Unmarshal(data, vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Vectors) == 0 || len(vectors.Refusals) == 0 {
		t.Fatal("no vectors")
	}
	return vectors
}

func mustHex(t *testing.T, text string) []byte {
	t.Helper()
	data, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustNetworkId(t *testing.T, text string) sidecar.Id {
	t.Helper()
	var networkId sidecar.Id
	if copy(networkId[:], mustHex(t, text)) != len(networkId) {
		t.Fatalf("network id %s", text)
	}
	return networkId
}

// Every vector's key, by id, once.
func vectorKeys(t *testing.T, vectors *xUrRefVectors) []*SmtpXUrRefKey {
	t.Helper()
	keys := []*SmtpXUrRefKey{}
	seen := map[uint8]bool{}
	for _, vector := range vectors.Vectors {
		if !seen[vector.KeyId] {
			seen[vector.KeyId] = true
			keys = append(keys, &SmtpXUrRefKey{KeyId: vector.KeyId, Key: mustHex(t, vector.Key)})
		}
	}
	return keys
}

func TestSmtpXUrRefVectors(t *testing.T) {
	vectors := readXUrRefVectors(t)
	keys := vectorKeys(t, vectors)
	for _, vector := range vectors.Vectors {
		key := &SmtpXUrRefKey{KeyId: vector.KeyId, Key: mustHex(t, vector.Key)}
		networkId := mustNetworkId(t, vector.NetworkId)
		sendId := mustHex(t, vector.SendId)
		issued, err := IssueSmtpXUrRef(key, sendId, networkId, vector.Day)
		if err != nil {
			t.Fatal(err)
		}
		if issued != vector.XUrRef {
			t.Errorf("issued %s, the vector says %s", issued, vector.XUrRef)
		}
		if len(issued) != 36 || !smtpXUrRefPattern.MatchString(issued) {
			t.Errorf("%s is not plan-SMTP-small-readings#3's form, which the report parser reads", issued)
		}
		ref, err := VerifySmtpXUrRef(keys, vector.XUrRef, networkId, vector.Day)
		if err != nil {
			t.Errorf("%s: %v", vector.XUrRef, err)
			continue
		}
		if ref.KeyId != vector.KeyId || !bytes.Equal(ref.SendId, sendId) {
			t.Errorf("%s names key %d and send %x", vector.XUrRef, ref.KeyId, ref.SendId)
		}
	}
}

func TestSmtpXUrRefRefusals(t *testing.T) {
	vectors := readXUrRefVectors(t)
	keys := vectorKeys(t, vectors)
	for _, refusal := range vectors.Refusals {
		if _, err := VerifySmtpXUrRef(keys, refusal.XUrRef, mustNetworkId(t, refusal.NetworkId), refusal.Day); !errors.Is(err, ErrSmtpXUrRefInvalid) {
			t.Errorf("%s: %q verified: %v", refusal.Why, refusal.XUrRef, err)
		}
	}
}

// §22.5's X-UR-Ref MAC: a reference a sidecar of one network was issued fails under another's id, so a
// recipient on the shared addresses cannot paste it into a complaint against that network.
func TestSmtpXUrRefReplayUnderAnotherNetworkFails(t *testing.T) {
	key := &SmtpXUrRefKey{KeyId: 7, Key: bytes.Repeat([]byte{0x33}, 32)}
	sendId, err := NewSmtpSendId()
	if err != nil {
		t.Fatal(err)
	}
	networkA, networkB := sidecar.NewId(), sidecar.NewId()
	day := SmtpXUrRefDay(time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC))
	issued, err := IssueSmtpXUrRef(key, sendId, networkA, day)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySmtpXUrRef([]*SmtpXUrRefKey{key}, issued, networkA, day); err != nil {
		t.Fatalf("under its own network: %v", err)
	}
	if _, err := VerifySmtpXUrRef([]*SmtpXUrRefKey{key}, issued, networkB, day); !errors.Is(err, ErrSmtpXUrRefInvalid) {
		t.Fatalf("under another network: %v", err)
	}
}

func TestSmtpXUrRefIssueRefusesMalformedInput(t *testing.T) {
	key := &SmtpXUrRefKey{KeyId: 1, Key: bytes.Repeat([]byte{0x33}, 32)}
	networkId := sidecar.NewId()
	for _, c := range []struct {
		name      string
		key       *SmtpXUrRefKey
		sendId    []byte
		networkId sidecar.Id
	}{
		{name: "no key", key: nil, sendId: make([]byte, 12), networkId: networkId},
		{name: "key id 0", key: &SmtpXUrRefKey{KeyId: 0, Key: key.Key}, sendId: make([]byte, 12), networkId: networkId},
		{name: "a short send id", key: key, sendId: make([]byte, 11), networkId: networkId},
		{name: "no network", key: key, sendId: make([]byte, 12), networkId: sidecar.Id{}},
	} {
		if _, err := IssueSmtpXUrRef(c.key, c.sendId, c.networkId, 1); !errors.Is(err, ErrSmtpIssueRefused) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestSmtpFeedbackIdWidthsAndBurnersShareTheToken(t *testing.T) {
	token := "abcdefghijklmnopqrstuvwxyz"
	for _, c := range []struct {
		burner bool
		tier   string
		want   string
	}{
		{burner: false, tier: "free", want: "n:c:" + token + ":urnetwork"},
		{burner: false, tier: "pro", want: "n:p:" + token + ":urnetwork"},
		{burner: false, tier: "team", want: "n:t:" + token + ":urnetwork"},
		{burner: true, tier: "free", want: "b:c:" + token + ":urnetwork"},
		{burner: true, tier: "team", want: "b:t:" + token + ":urnetwork"},
	} {
		got, err := IssueSmtpFeedbackId(c.burner, c.tier, token)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want || len(got) != 40 || !smtpFeedbackIdPattern.MatchString(got) {
			t.Errorf("%q, want %q", got, c.want)
		}
	}
	network, _ := IssueSmtpFeedbackId(false, "pro", token)
	burner, _ := IssueSmtpFeedbackId(true, "pro", token)
	if network[2:] != burner[2:] {
		t.Fatal("a burner's Feedback-ID names another token than its network's")
	}
	for _, c := range []struct {
		tier  string
		token string
	}{
		{tier: "enterprise", token: token},
		{tier: "pro", token: strings.ToUpper(token)},
		{tier: "pro", token: token[:25]},
		{tier: "pro", token: token[:25] + "1"},
	} {
		if _, err := IssueSmtpFeedbackId(false, c.tier, c.token); !errors.Is(err, ErrSmtpIssueRefused) {
			t.Errorf("tier %q token %q: %v", c.tier, c.token, err)
		}
	}
}

func TestSmtpIssuerIssuesUnderTheIssueKeyAndVerifiesUnderAny(t *testing.T) {
	settings := DefaultSmtpEdgeSettings()
	old := &SmtpXUrRefKey{KeyId: 1, Key: bytes.Repeat([]byte{0x01}, 32)}
	current := &SmtpXUrRefKey{KeyId: 2, Key: bytes.Repeat([]byte{0x02}, 32)}
	settings.XUrRefKeys = []*SmtpXUrRefKey{old, current}
	settings.XUrRefIssueKeyId = 2
	issuer := newSmtpIssuer(settings)
	if issuer == nil {
		t.Fatal("no issuer")
	}
	now := time.Date(2026, time.November, 15, 23, 59, 0, 0, time.UTC)
	networkId := sidecar.NewId()
	issued, err := issuer.issue(networkId, false, "pro", "abcdefghijklmnopqrstuvwxyz", now)
	if err != nil {
		t.Fatal(err)
	}
	if issued.KeyId != 2 || len(issued.SendId) != SmtpSendIdByteCount {
		t.Fatalf("issued %+v", issued)
	}
	if _, err := VerifySmtpXUrRef(settings.XUrRefKeys, issued.XUrRef, networkId, SmtpXUrRefDay(now)); err != nil {
		t.Fatal(err)
	}
	// a reference under the retiring key still verifies through the overlap
	retiring, err := IssueSmtpXUrRef(old, issued.SendId, networkId, SmtpXUrRefDay(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySmtpXUrRef(settings.XUrRefKeys, retiring, networkId, SmtpXUrRefDay(now)); err != nil {
		t.Fatal(err)
	}
	// another day's MAC fails: the day is UTC, as the send record's
	if _, err := VerifySmtpXUrRef(settings.XUrRefKeys, issued.XUrRef, networkId, SmtpXUrRefDay(now.Add(time.Minute))); !errors.Is(err, ErrSmtpXUrRefInvalid) {
		t.Fatalf("the next UTC day: %v", err)
	}
}

func TestSmtpIssuerNeedsItsIssueKey(t *testing.T) {
	settings := DefaultSmtpEdgeSettings()
	settings.Root = "root.example"
	settings.ReportHostName = "rpt.root.example"
	settings.XUrRefKeys = []*SmtpXUrRefKey{{KeyId: 3, Key: bytes.Repeat([]byte{0x03}, 32)}}
	if newSmtpIssuer(settings) != nil {
		t.Fatal("an issuer with no key under x_ur_ref_issue_key_id")
	}
	if err := settings.Validate(); !errors.Is(err, ErrSmtpEdgeSettingsRefused) {
		t.Fatalf("validated: %v", err)
	}
	settings.XUrRefKeys = []*SmtpXUrRefKey{{KeyId: 1, Key: bytes.Repeat([]byte{0x03}, 31)}}
	if err := settings.Validate(); !errors.Is(err, ErrSmtpEdgeSettingsRefused) {
		t.Fatalf("a short key validated: %v", err)
	}
	settings.XUrRefKeys = []*SmtpXUrRefKey{{KeyId: 1, Key: bytes.Repeat([]byte{0x03}, 32)}, {KeyId: 1, Key: bytes.Repeat([]byte{0x04}, 32)}}
	if err := settings.Validate(); !errors.Is(err, ErrSmtpEdgeSettingsRefused) {
		t.Fatalf("a repeated id validated: %v", err)
	}
	settings.XUrRefKeys = nil
	if err := settings.Validate(); err != nil {
		t.Fatalf("no keys, as the intake loads them: %v", err)
	}
}
