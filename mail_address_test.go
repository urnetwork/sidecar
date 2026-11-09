// §15.8's grammar (MAIL-M7-02): each form, each reserved name and alias zones, by table, and the fuzz target's
// property over its seeds, which are embedded since the page Worker's leg has no file system to read them from.

package sidecar

import (
	"embed"
	"errors"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"testing"
)

//go:embed testdata/fuzz/FuzzMailRecipient
var testMailRecipientFiles embed.FS

// The root, a network's label and its alias in these tests: synthetic, under .example.
const (
	testMailRoot  = "root.example"
	testMailLabel = "k3j4h5g6f7"
	testMailAlias = "acme-labs"
)

// Each form, alias zones and scopes included, with what the parse must give.
func TestParseMailRecipientForms(t *testing.T) {
	labelZone := MailZone{Root: testMailRoot, Net: testMailLabel}
	aliasZone := MailZone{Root: testMailRoot, Net: testMailAlias}
	scopeZone := MailZone{Root: testMailRoot, Net: testMailLabel, Scope: "ops"}
	aliasScopeZone := MailZone{Root: testMailRoot, Net: testMailAlias, Scope: "ops"}
	cases := []struct {
		address string
		want    MailRecipient
	}{
		{address: "admin@k3j4h5g6f7.root.example", want: MailRecipient{Kind: MailAddressKindAdmin, LocalPart: "admin", Zone: labelZone}},
		{address: "postmaster@k3j4h5g6f7.root.example", want: MailRecipient{Kind: MailAddressKindAdmin, LocalPart: "postmaster", Zone: labelZone}},
		{address: "abuse@acme-labs.root.example", want: MailRecipient{Kind: MailAddressKindAdmin, LocalPart: "abuse", Zone: aliasZone}},
		{address: "PostMaster@K3J4H5G6F7.Root.Example", want: MailRecipient{Kind: MailAddressKindAdmin, LocalPart: "postmaster", Zone: labelZone}},
		{address: "ada@k3j4h5g6f7.root.example", want: MailRecipient{Kind: MailAddressKindName, LocalPart: "ada", Zone: labelZone}},
		{address: "ada.lovelace_1-x@acme-labs.root.example", want: MailRecipient{Kind: MailAddressKindName, LocalPart: "ada.lovelace_1-x", Zone: aliasZone}},
		{address: "0@k3j4h5g6f7.root.example", want: MailRecipient{Kind: MailAddressKindName, LocalPart: "0", Zone: labelZone}},
		{address: strings.Repeat("a", 64) + "@k3j4h5g6f7.root.example", want: MailRecipient{Kind: MailAddressKindName, LocalPart: strings.Repeat("a", 64), Zone: labelZone}},
		// reserved from creation, but they parse, and the lookup finds no record
		{address: "mailer-daemon@k3j4h5g6f7.root.example", want: MailRecipient{Kind: MailAddressKindName, LocalPart: "mailer-daemon", Zone: labelZone}},
		{address: "bounces@k3j4h5g6f7.root.example", want: MailRecipient{Kind: MailAddressKindName, LocalPart: "bounces", Zone: labelZone}},
		{address: "r-k5mzq7x2@k3j4h5g6f7.root.example", want: MailRecipient{Kind: MailAddressKindName, LocalPart: "r-k5mzq7x2", Zone: labelZone}},
		{address: "ada@ops.k3j4h5g6f7.root.example", want: MailRecipient{Kind: MailAddressKindName, LocalPart: "ada", Zone: scopeZone}},
		{address: "admin@ops.k3j4h5g6f7.root.example", want: MailRecipient{Kind: MailAddressKindAdmin, LocalPart: "admin", Zone: scopeZone}},
		{address: "abuse@ops.acme-labs.root.example", want: MailRecipient{Kind: MailAddressKindAdmin, LocalPart: "abuse", Zone: aliasScopeZone}},
		{address: "bounces+abc123@b.k3j4h5g6f7.root.example", want: MailRecipient{Kind: MailAddressKindBounce, LocalPart: "bounces+abc123", Zone: labelZone, Token: "abc123"}},
		{address: "bounces+a.b_c-d@b.acme-labs.root.example", want: MailRecipient{Kind: MailAddressKindBounce, LocalPart: "bounces+a.b_c-d", Zone: aliasZone, Token: "a.b_c-d"}},
		{address: "shop@otter-4821.k3j4h5g6f7.root.example", want: MailRecipient{Kind: MailAddressKindBurner, LocalPart: "shop", Zone: labelZone, BurnerLabel: "otter-4821"}},
		// a burner takes any local part, admin's included: the label's mailbox gets it
		{address: "admin@otter-4821.acme-labs.root.example", want: MailRecipient{Kind: MailAddressKindBurner, LocalPart: "admin", Zone: aliasZone, BurnerLabel: "otter-4821"}},
		{address: "r-k5mzq7x2@otter-4821.k3j4h5g6f7.root.example", want: MailRecipient{Kind: MailAddressKindReverseAlias, LocalPart: "r-k5mzq7x2", Zone: labelZone, BurnerLabel: "otter-4821", Token: "k5mzq7x2"}},
	}
	for _, c := range cases {
		recipient, err := ParseMailRecipient(testMailRoot, c.address)
		if err != nil {
			t.Errorf("%s: %v", c.address, err)
			continue
		}
		if recipient != c.want {
			t.Errorf("%s: got %+v, want %+v", c.address, recipient, c.want)
		}
		if recipient.Address() != strings.ToLower(c.address) {
			t.Errorf("%s: spelled %s", c.address, recipient.Address())
		}
		again, err := ParseMailRecipient(testMailRoot, recipient.Address())
		if err != nil || again != recipient {
			t.Errorf("%s: its spelling parses to %+v, %v", c.address, again, err)
		}
	}
}

// Everything else, each refused as ErrMailRecipientInvalid with the address unrepeated.
func TestParseMailRecipientRefusals(t *testing.T) {
	cases := []string{
		"",
		"ada",
		"@k3j4h5g6f7.root.example",
		"ada@",
		"ada@@k3j4h5g6f7.root.example",
		"a@b@k3j4h5g6f7.root.example",
		strings.Repeat("a", 65) + "@k3j4h5g6f7.root.example",
		`"ada"@k3j4h5g6f7.root.example`,
		"ada+tag@k3j4h5g6f7.root.example",
		"ada lovelace@k3j4h5g6f7.root.example",
		"éda@k3j4h5g6f7.root.example",
		".ada@k3j4h5g6f7.root.example",
		"-ada@k3j4h5g6f7.root.example",
		"_ada@k3j4h5g6f7.root.example",
		"ada\r\n@k3j4h5g6f7.root.example",
		"ada@root.example",
		"ada@k3j4h5g6f7.other.example",
		"ada@k3j4h5g6f7.root.example.",
		"ada@k3j4h5g6f7.root.example.other",
		"ada@[192.0.2.1]",
		"ada@k3j4h5g6f7evilroot.example",
		"ada@.k3j4h5g6f7.root.example",
		"ada@k3j4h5g6f7..root.example",
		"ada@-k3j4h5g6f7.root.example",
		"ada@k3j4h5g6f7-.root.example",
		"ada@k3_j4h5g6f7.root.example",
		// a word-number label is a burner's, never a network's or a scope's
		"ada@otter-4821.root.example",
		// b is the bounce zone, and mx, mail and mta-sts are hosts
		"ada@b.root.example",
		"ada@mx.root.example",
		"ada@mx.k3j4h5g6f7.root.example",
		"ada@mail.k3j4h5g6f7.root.example",
		"ada@mta-sts.k3j4h5g6f7.root.example",
		// the bounce zone takes only bounces+<token>
		"ada@b.k3j4h5g6f7.root.example",
		"admin@b.k3j4h5g6f7.root.example",
		"bounces@b.k3j4h5g6f7.root.example",
		"bounces+@b.k3j4h5g6f7.root.example",
		"bounces+a+b@b.k3j4h5g6f7.root.example",
		"bounces+a/b@b.k3j4h5g6f7.root.example",
		"bounces+" + strings.Repeat("a", 57) + "@b.k3j4h5g6f7.root.example",
		// a reverse alias needs a token, and a burner's local part the grammar
		"r-@otter-4821.k3j4h5g6f7.root.example",
		"shop+x@otter-4821.k3j4h5g6f7.root.example",
		// no form sits under a scope but the scope's own names
		"ada@x.ops.k3j4h5g6f7.root.example",
		"shop@otter-4821.ops.k3j4h5g6f7.root.example",
		"bounces+abc@b.ops.k3j4h5g6f7.root.example",
		"ada@" + strings.Repeat("a", 64) + ".root.example",
		"ada@" + strings.Repeat(strings.Repeat("a", 63)+".", 4) + "root.example",
	}
	for _, address := range cases {
		recipient, err := ParseMailRecipient(testMailRoot, address)
		if !errors.Is(err, ErrMailRecipientInvalid) {
			t.Errorf("%q: got %+v, %v", address, recipient, err)
			continue
		}
		if recipient != (MailRecipient{}) {
			t.Errorf("%q: a refusal returned %+v", address, recipient)
		}
		if strings.Contains(address, "@k3") && strings.Contains(err.Error(), address) {
			t.Errorf("%q: the error repeats the address", address)
		}
	}
}

// A root is a domain name of two or more labels, in any ASCII case and with or without its trailing dot.
func TestParseMailRecipientRoots(t *testing.T) {
	for _, root := range []string{"root.example", "Root.Example.", " root.example "} {
		recipient, err := ParseMailRecipient(root, "ada@k3j4h5g6f7.root.example")
		if err != nil || recipient.Zone.Root != "root.example" {
			t.Errorf("%q: %+v, %v", root, recipient, err)
		}
	}
	for _, root := range []string{"", "example", ".", "root..example", "root_x.example"} {
		if _, err := ParseMailRecipient(root, "ada@k3j4h5g6f7."+root); !errors.Is(err, ErrMailRecipientInvalid) {
			t.Errorf("%q: %v", root, err)
		}
	}
	// a deeper root takes the same forms beneath it
	recipient, err := ParseMailRecipient("mail.root.example", "shop@otter-4821.k3j4h5g6f7.mail.root.example")
	if err != nil || recipient.Kind != MailAddressKindBurner || recipient.Zone.Net != testMailLabel {
		t.Errorf("deeper root: %+v, %v", recipient, err)
	}
	// an address at every bound at once parses: a 64-byte local part and a 253-byte domain of 63-byte labels
	longRoot := strings.Repeat("r", 61) + "." + strings.Repeat("s", 63)
	longest := strings.Repeat("a", 64) + "@" + strings.Repeat("o", 63) + "." + strings.Repeat("n", 63) + "." + longRoot
	if len(longest) != MailAddressMaxByteCount {
		t.Fatalf("the longest case takes %d B", len(longest))
	}
	recipient, err = ParseMailRecipient(longRoot, longest)
	if err != nil || recipient.Address() != longest || recipient.Zone.Scope != strings.Repeat("o", 63) {
		t.Errorf("the longest address: %+v, %v", recipient, err)
	}
	// and one byte more, anywhere, does not
	for _, longer := range []string{"a" + longest, strings.Replace(longest, "@", "@o", 1), longest + "x"} {
		if _, err := ParseMailRecipient(longRoot, longer); !errors.Is(err, ErrMailRecipientInvalid) {
			t.Errorf("an address past its bound: %v", err)
		}
	}
	if _, err := ParseMailRecipient(testMailRoot, strings.Repeat("a", MailAddressMaxByteCount+1)); !errors.Is(err, ErrMailRecipientInvalid) {
		t.Errorf("an address past its bound: %v", err)
	}
}

// §15.8's local parts: the grammar, and what is reserved from creation.
func TestMailLocalParts(t *testing.T) {
	valid := []string{"a", "0", "ada", "ada.lovelace", "a_b-c.d", "admin", "r-x", strings.Repeat("z", 64)}
	for _, localPart := range valid {
		if !ValidMailLocalPart(localPart) {
			t.Errorf("%q is not valid", localPart)
		}
	}
	invalid := []string{"", "Ada", ".a", "-a", "_a", "a+b", "a b", "a@b", "é", strings.Repeat("z", 65), "a\x00"}
	for _, localPart := range invalid {
		if ValidMailLocalPart(localPart) {
			t.Errorf("%q is valid", localPart)
		}
		if !errors.Is(ValidateNewMailLocalPart(localPart), ErrMailLocalPartInvalid) {
			t.Errorf("%q: %v", localPart, ValidateNewMailLocalPart(localPart))
		}
	}
	reserved := []string{"admin", "postmaster", "abuse", "mailer-daemon", "bounces", "r-", "r-x", "r-k5mzq7x2"}
	for _, localPart := range reserved {
		if !IsReservedMailLocalPart(localPart) {
			t.Errorf("%q is not reserved", localPart)
		}
		if !errors.Is(ValidateNewMailLocalPart(localPart), ErrMailLocalPartReserved) {
			t.Errorf("%q: %v", localPart, ValidateNewMailLocalPart(localPart))
		}
	}
	free := []string{"ada", "rx", "r", "radmin", "admins", "abuser", "bounce", "post-master", "mailer"}
	for _, localPart := range free {
		if IsReservedMailLocalPart(localPart) || ValidateNewMailLocalPart(localPart) != nil {
			t.Errorf("%q is refused: %v", localPart, ValidateNewMailLocalPart(localPart))
		}
	}
}

// A zone's domain, and the networks it names: the label, the alias and an alias still retiring, under one root.
func TestMailZone(t *testing.T) {
	if domain := (MailZone{Root: testMailRoot, Net: testMailLabel}).Domain(); domain != "k3j4h5g6f7.root.example" {
		t.Errorf("domain %s", domain)
	}
	if domain := (MailZone{Root: testMailRoot, Net: testMailAlias, Scope: "ops"}).Domain(); domain != "ops.acme-labs.root.example" {
		t.Errorf("scope domain %s", domain)
	}
	row := NetworkLabelRow{
		Root:            testMailRoot,
		NetworkId:       Id{1},
		Label:           testMailLabel,
		Alias:           testMailAlias,
		RetiringAliases: []string{"old-acme"},
	}
	for _, net := range []string{testMailLabel, testMailAlias, "old-acme"} {
		if !(MailZone{Root: testMailRoot, Net: net, Scope: "ops"}).OfNetwork(row) {
			t.Errorf("%s names no network", net)
		}
	}
	others := []MailZone{
		{Root: "other.example", Net: testMailLabel},
		{Root: testMailRoot, Net: "z9y8x7w6v5"},
		{Root: testMailRoot},
	}
	for _, zone := range others {
		if zone.OfNetwork(row) {
			t.Errorf("%+v names the network", zone)
		}
	}
	// a network with no label or alias yet names no zone, the empty one included
	if (MailZone{Root: testMailRoot}).OfNetwork(NetworkLabelRow{Root: testMailRoot, NetworkId: Id{1}}) {
		t.Error("an empty net names a network with no label")
	}
	// a recipient's domain puts b. and <blabel>. under its zone
	recipient, err := ParseMailRecipient(testMailRoot, "bounces+t@b.acme-labs.root.example")
	if err != nil || recipient.Domain() != "b.acme-labs.root.example" || !recipient.Zone.OfNetwork(row) {
		t.Errorf("bounce: %+v, %v", recipient, err)
	}
}

// The property FuzzMailRecipient holds, or why not. A refusal is ErrMailRecipientInvalid and never repeats an
// address; an acceptance spells the address it was given, lowercase, parses again to itself and keeps each form's
// shape.
func checkMailRecipient(root string, address string) string {
	recipient, err := ParseMailRecipient(root, address)
	if err != nil {
		if !errors.Is(err, ErrMailRecipientInvalid) {
			return "refused with another error: " + err.Error()
		}
		if recipient != (MailRecipient{}) {
			return "a refusal returned a recipient"
		}
		// no fixed reason has a dot after an @, so an address with one is never in the text by chance
		if at := strings.Index(address, "@"); 0 <= at && strings.Contains(address[at:], ".") && strings.Contains(err.Error(), address) {
			return "the error repeats the address"
		}
		return ""
	}
	if recipient.Address() != dnsAsciiLower(address) {
		return "spelled another address"
	}
	if MailAddressMaxByteCount < len(recipient.Address()) {
		return "an address past its bound"
	}
	again, err := ParseMailRecipient(root, recipient.Address())
	if err != nil || again != recipient {
		return "its spelling parses to another recipient"
	}
	zone := recipient.Zone
	if zone.Root != canonicalNetworkLabelRoot(root) || !validMailZoneLabel(zone.Net) || (zone.Scope != "" && !validMailZoneLabel(zone.Scope)) {
		return "a zone outside the grammar"
	}
	switch recipient.Kind {
	case MailAddressKindAdmin:
		if !slices.Contains(mailAdminLocalParts, recipient.LocalPart) || recipient.BurnerLabel != "" || recipient.Token != "" {
			return "an admin address of another shape"
		}
	case MailAddressKindName:
		if !ValidMailLocalPart(recipient.LocalPart) || slices.Contains(mailAdminLocalParts, recipient.LocalPart) || recipient.BurnerLabel != "" || recipient.Token != "" {
			return "a name of another shape"
		}
	case MailAddressKindBounce:
		if recipient.LocalPart != mailBouncePrefix+recipient.Token || !validMailToken(recipient.Token) || zone.Scope != "" || recipient.BurnerLabel != "" {
			return "a bounce of another shape"
		}
	case MailAddressKindBurner:
		if !ValidMailLocalPart(recipient.LocalPart) || strings.HasPrefix(recipient.LocalPart, mailReverseAliasPrefix) || !IsWordNumberDnsLabel(recipient.BurnerLabel) || zone.Scope != "" || recipient.Token != "" {
			return "a burner of another shape"
		}
	case MailAddressKindReverseAlias:
		if recipient.LocalPart != mailReverseAliasPrefix+recipient.Token || recipient.Token == "" || !ValidMailLocalPart(recipient.LocalPart) || !IsWordNumberDnsLabel(recipient.BurnerLabel) || zone.Scope != "" {
			return "a reverse alias of another shape"
		}
	default:
		return "an unknown kind"
	}
	return ""
}

// One seed of testdata/fuzz/FuzzMailRecipient: its root and address.
func testMailRecipientSeed(t *testing.T, name string, seed []byte) (string, string) {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(string(seed)), "\n")
	if len(lines) != 3 || lines[0] != "go test fuzz v1" {
		t.Fatalf("%s: not a corpus file of two strings", name)
	}
	values := []string{}
	for _, line := range lines[1:] {
		quoted, found := strings.CutPrefix(line, "string(")
		if !found {
			t.Fatalf("%s: not a string value", name)
		}
		value, err := strconv.Unquote(strings.TrimSuffix(quoted, ")"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		values = append(values, value)
	}
	return values[0], values[1]
}

// The seeds hold the fuzz target's property on every leg: go test runs them through FuzzMailRecipient only where a
// file system lets it read them, and the Worker has none.
func TestMailRecipientFuzzSeedsHold(t *testing.T) {
	const directory = "testdata/fuzz/FuzzMailRecipient"
	entries, err := fs.ReadDir(testMailRecipientFiles, directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 8 {
		t.Fatalf("%d seeds", len(entries))
	}
	for _, entry := range entries {
		seed, err := testMailRecipientFiles.ReadFile(directory + "/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		root, address := testMailRecipientSeed(t, entry.Name(), seed)
		if failure := checkMailRecipient(root, address); failure != "" {
			t.Errorf("%s: %s", entry.Name(), failure)
		}
	}
}
