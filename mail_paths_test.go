// §15.7's layout (MAIL-M7-02): <h>, <yyyymm> and whole paths held to testdata/mail/vectors.yml on every leg, whose
// rows Python wrote, so these and mail_paths.go share no code; the sealed receive time, which makes racing readers
// write one path; the names each family refuses; and DIRECTORY_FULL told apart.

package sidecar

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// <h> of each name vectors.yml pins, the address, the burner label and both binary spellings among them.
func TestMailShardVectors(t *testing.T) {
	items := parseMailVectors(t)["names"]
	if len(items) == 0 {
		t.Fatal("no names")
	}
	for _, item := range items {
		if h := MailShard(item["name"]); h != item["h"] {
			t.Errorf("%s: <h> is %s, want %s", item["name"], h, item["h"])
		}
		if item["hex"] == "" {
			continue
		}
		raw, err := hex.DecodeString(item["hex"])
		if err != nil {
			t.Fatal(err)
		}
		if name := mailBinaryName(raw); name != item["name"] {
			t.Errorf("%s spells %s", item["hex"], name)
		}
	}
}

// <yyyymm> of each sealed time vectors.yml pins, across a year's end, in UTC whatever this leg's zone.
func TestMailYearMonthVectors(t *testing.T) {
	items := parseMailVectors(t)["months"]
	if len(items) == 0 {
		t.Fatal("no months")
	}
	for _, item := range items {
		month := MailYearMonthOf(mailVectorNumber(t, item, "millis"))
		if month.String() != item["month"] {
			t.Errorf("%s is %s, want %s", item["millis"], month, item["month"])
		}
		parsed, ok := ParseMailYearMonth(item["month"])
		if !ok || parsed != month {
			t.Errorf("%s parses to %v, %t", item["month"], parsed, ok)
		}
	}
}

// Every family's whole path, byte for byte.
func TestMailPathVectors(t *testing.T) {
	items := parseMailVectors(t)["paths"]
	families := map[string]bool{}
	for _, item := range items {
		families[item["name"]] = true
		var raw []byte
		if item["hex"] != "" {
			var err error
			raw, err = hex.DecodeString(item["hex"])
			if err != nil {
				t.Fatal(err)
			}
		}
		month := MailYearMonth(0)
		if item["millis"] != "" {
			month = MailYearMonthOf(mailVectorNumber(t, item, "millis"))
		}
		var path string
		var err error
		switch item["name"] {
		case "message":
			path = MailMessagePath(month, Id(raw))
		case "group_ref":
			path = MailGroupRefPath(month, Id(raw))
		case "index":
			path = MailIndexPath(month, mailVectorNumber(t, item, "n"))
		case "flag":
			path = MailFlagPath(month, mailVectorNumber(t, item, "n"))
		case "vault":
			path = MailVaultPath(Id(raw))
		case "outbox":
			path, err = MailOutboxPath(raw)
		case "outcome":
			path, err = MailOutcomePath(raw)
		case "prover":
			path = MailProverPath(Id(raw))
		case "reverse_alias":
			path, err = MailReverseAliasPath(item["token"])
		case "address":
			path, err = MailAddressPath(item["address"])
		case "burner":
			path, err = MailBurnerPath(item["label"])
		default:
			t.Fatalf("a path of no family: %s", item["name"])
		}
		if err != nil {
			t.Errorf("%s: %v", item["name"], err)
			continue
		}
		if path != item["path"] {
			t.Errorf("%s: %s, want %s", item["name"], path, item["path"])
		}
		// a name evs can hold, each component under §11.7's 64-byte row but an address
		names, err := evsPathNames(path)
		if err != nil {
			t.Errorf("%s: %v", item["name"], err)
		}
		if item["name"] != "address" && len(names[len(names)-1]) >= 64 {
			t.Errorf("%s: a last name of %d B", item["name"], len(names[len(names)-1]))
		}
	}
	for _, family := range []string{"message", "group_ref", "index", "flag", "vault", "outbox", "outcome", "prover", "reverse_alias", "address", "burner"} {
		if !families[family] {
			t.Errorf("no vector for %s", family)
		}
	}
	if MailForwardPath != "forward" || MailSpamModelPath != "s/model" {
		t.Errorf("%s, %s", MailForwardPath, MailSpamModelPath)
	}
	month := MailYearMonth(202611)
	if MailIndexDirectory(month) != "i/202611" || MailFlagDirectory(month) != "f/202611" {
		t.Errorf("%s, %s", MailIndexDirectory(month), MailFlagDirectory(month))
	}
}

// MAIL-FORMAT.md's order: the evidence's time, else the ingress's, else the push's signed time, 0 counting as absent.
func TestMailDepositReceiveTime(t *testing.T) {
	const evidenceMillis, ingressMillis, pushMillis = 1793923200040, 1793923200000, 1793923300000
	cases := []struct {
		deposit *protocol.MailDeposit
		want    uint64
	}{
		{deposit: &protocol.MailDeposit{
			Ingress:  &protocol.MailIngress{ReceiveTimeMillis: ingressMillis},
			Evidence: &protocol.MailAuthEvidence{ReceiveTimeMillis: evidenceMillis},
		}, want: evidenceMillis},
		{deposit: &protocol.MailDeposit{Ingress: &protocol.MailIngress{ReceiveTimeMillis: ingressMillis}}, want: ingressMillis},
		{deposit: &protocol.MailDeposit{
			Ingress:  &protocol.MailIngress{ReceiveTimeMillis: ingressMillis},
			Evidence: &protocol.MailAuthEvidence{},
		}, want: ingressMillis},
		{deposit: &protocol.MailDeposit{Ingress: &protocol.MailIngress{}, Evidence: &protocol.MailAuthEvidence{}}, want: pushMillis},
		// a same-network deposit has neither
		{deposit: &protocol.MailDeposit{Version: 1, MailFrom: []byte("ada@k3j4h5g6f7.root.example")}, want: pushMillis},
		{deposit: nil, want: pushMillis},
	}
	for index, c := range cases {
		if got := MailDepositReceiveTime(c.deposit, pushMillis); got != c.want {
			t.Errorf("case %d: %d, want %d", index, got, c.want)
		}
	}
}

// Two readers holding one deposit compute one m/ path whatever their own clocks say, a month's last millisecond
// included, where a reader that used its own time or the push's would take the next month.
func TestMailRacingReadersWriteOnePath(t *testing.T) {
	// 2026-12-31T23:59:59.999Z, the evidence's, and a push signed the next morning
	const sealedMillis, pushMillis = 1798761599999, 1798794000000
	deposit := &protocol.MailDeposit{
		Version:  1,
		Ingress:  &protocol.MailIngress{Version: 1, ReceiveTimeMillis: sealedMillis - 40},
		Evidence: &protocol.MailAuthEvidence{Version: 1, ReceiveTimeMillis: sealedMillis},
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(deposit)
	if err != nil {
		t.Fatal(err)
	}
	messageId := Id{0x01, 0x9a, 0x5b, 0x10, 0x7f}
	paths := []string{}
	for range 2 {
		reader := &protocol.MailDeposit{}
		if err := proto.Unmarshal(encoded, reader); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, MailMessagePath(MailYearMonthOf(MailDepositReceiveTime(reader, pushMillis)), messageId))
	}
	if paths[0] != paths[1] {
		t.Fatalf("%s and %s", paths[0], paths[1])
	}
	if !strings.HasPrefix(paths[0], "m/202612/") {
		t.Errorf("%s is not in the sealed month", paths[0])
	}
	if MailYearMonthOf(pushMillis).String() != "202701" {
		t.Errorf("the push's month is %s", MailYearMonthOf(pushMillis))
	}
}

// A month for every sealed time, held to 9999-12 at the top, and only six-digit months from 197001 parse.
func TestMailYearMonth(t *testing.T) {
	lastMillis := uint64(time.Date(9999, time.December, 31, 23, 59, 59, int(999*time.Millisecond), time.UTC).UnixMilli())
	cases := []struct {
		millis uint64
		want   string
	}{
		{millis: 0, want: "197001"},
		{millis: lastMillis, want: "999912"},
		{millis: lastMillis + 1, want: "999912"},
		{millis: math.MaxInt64, want: "999912"},
		{millis: math.MaxUint64, want: "999912"},
	}
	for _, c := range cases {
		if month := MailYearMonthOf(c.millis); month.String() != c.want {
			t.Errorf("%d: %s, want %s", c.millis, month, c.want)
		}
	}
	for _, text := range []string{"197001", "202611", "999912"} {
		if month, ok := ParseMailYearMonth(text); !ok || month.String() != text {
			t.Errorf("%s: %v, %t", text, month, ok)
		}
	}
	for _, text := range []string{"", "196912", "202600", "202613", "20261", "2026111", "20261a", "+20261", " 20261", "2026-1"} {
		if month, ok := ParseMailYearMonth(text); ok {
			t.Errorf("%q parses to %v", text, month)
		}
	}
	if month := MailYearMonth(202611); month.Year() != 2026 || month.Month() != time.November {
		t.Errorf("%d %s", month.Year(), month.Month())
	}
}

// <n> as a path spells it, and nothing else.
func TestParseMailSegmentNumber(t *testing.T) {
	for _, c := range []struct {
		text string
		want uint64
	}{
		{text: "0", want: 0},
		{text: "7", want: 7},
		{text: "4095", want: 4095},
		{text: "18446744073709551615", want: math.MaxUint64},
	} {
		if n, ok := ParseMailSegmentNumber(c.text); !ok || n != c.want {
			t.Errorf("%s: %d, %t", c.text, n, ok)
		}
	}
	for _, text := range []string{"", "00", "01", "-1", "+1", "1a", " 1", "18446744073709551616"} {
		if n, ok := ParseMailSegmentNumber(text); ok {
			t.Errorf("%q parses to %d", text, n)
		}
	}
	for _, n := range []uint64{0, 1, 4096, math.MaxUint64} {
		path := MailIndexPath(MailYearMonth(202611), n)
		parsed, ok := ParseMailSegmentNumber(path[strings.LastIndex(path, "/")+1:])
		if !ok || parsed != n {
			t.Errorf("%s: %d, %t", path, parsed, ok)
		}
	}
}

// Each family refuses a name it cannot hold, and the error never repeats it.
func TestMailPathsRefuseNames(t *testing.T) {
	for _, length := range []int{0, 16, 31, 33} {
		if _, err := MailOutboxPath(make([]byte, length)); !errors.Is(err, ErrMailPathInvalid) {
			t.Errorf("outbox, a key of %d bytes: %v", length, err)
		}
		if _, err := MailOutcomePath(make([]byte, length)); !errors.Is(err, ErrMailPathInvalid) {
			t.Errorf("outcome, a key of %d bytes: %v", length, err)
		}
	}
	for _, address := range []string{"", "Ada@k3j4h5g6f7.root.example", "a/b@k3j4h5g6f7.root.example", "a\x00@x", strings.Repeat("a", MailAddressMaxByteCount+1)} {
		_, err := MailAddressPath(address)
		if !errors.Is(err, ErrMailPathInvalid) {
			t.Errorf("address %q: %v", address, err)
		} else if address != "" && strings.Contains(err.Error(), address) {
			t.Errorf("address %q: the error repeats it", address)
		}
	}
	for _, label := range []string{"", "otter", "Otter-4821", "otter-48210", "otter-4821/x", "4821-otter"} {
		if _, err := MailBurnerPath(label); !errors.Is(err, ErrMailPathInvalid) {
			t.Errorf("burner %q: %v", label, err)
		}
	}
	for _, token := range []string{"", "a/b", "A", "a+b", strings.Repeat("t", 63)} {
		if _, err := MailReverseAliasPath(token); !errors.Is(err, ErrMailPathInvalid) {
			t.Errorf("reverse alias %q: %v", token, err)
		}
	}
	if _, err := MailReverseAliasPath(strings.Repeat("t", 62)); err != nil {
		t.Errorf("the longest token: %v", err)
	}
	// a parsed recipient's own pieces always make paths
	recipient, err := ParseMailRecipient(testMailRoot, "r-k5mzq7x2@otter-4821.k3j4h5g6f7.root.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, build := range []func() (string, error){
		func() (string, error) { return MailAddressPath(recipient.Address()) },
		func() (string, error) { return MailBurnerPath(recipient.BurnerLabel) },
		func() (string, error) { return MailReverseAliasPath(recipient.Token) },
	} {
		if _, err := build(); err != nil {
			t.Error(err)
		}
	}
}

// DIRECTORY_FULL, bare or wrapped, is told apart from every other answer, so a writer surfaces it and never retries.
func TestIsMailDirectoryFull(t *testing.T) {
	full := &EvsError{Status: 409, Code: protocol.EvsRefusalCode_EVS_REFUSAL_DIRECTORY_FULL, Recorded: true}
	if !IsMailDirectoryFull(full) || !IsMailDirectoryFull(fmt.Errorf("mail: %w", full)) {
		t.Error("DIRECTORY_FULL not seen")
	}
	others := []error{
		nil,
		errors.New("directory full"),
		&EvsError{Status: 409, Code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT},
		&EvsError{Status: 429, Code: protocol.EvsRefusalCode_EVS_REFUSAL_BUSY},
		&EvsError{Status: 412, Code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH_DUE},
	}
	for _, err := range others {
		if IsMailDirectoryFull(err) {
			t.Errorf("%v read as DIRECTORY_FULL", err)
		}
	}
	// a full directory is a refusal evs records, never one that refuses nothing and invites a retry
	if full.RefusesNothing() {
		t.Error("DIRECTORY_FULL refuses nothing")
	}
}
