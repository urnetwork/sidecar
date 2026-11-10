// MAIL-M7-10's labels and operator list on every leg the root's tests run on, the sidecar_http Worker included, so
// every file read is embedded. testdata/mail/labels.yml's T1 vectors cover each rule; FS-39's M7 rest holds that
// later DNS leaves the reception-time label, a recheck shown apart, and that REQUIRETLS an active second hop added
// labels as stated with no exact path claim; §22.7's rows hold a listed operator's inference basis, an MTA-STS-only
// operator's burner mail validated with no MTA-STS in its basis, and a DANE-listed one's citing DANE; FS-121's holds
// that no incomplete evidence validates; and a text scan refuses "end-to-end" in label strings. mail_operators_gen.go
// is held to mail_operators.yml here, and regenerated with
//
//	SIDECAR_REGENERATE_MAIL_OPERATORS=1 go test -run '^TestMailOperatorsGenIsCurrent$' .
//
// which mail_operators.go's go:generate line runs. Every name is synthetic.

package sidecar

import (
	_ "embed"
	"errors"
	"fmt"
	"go/format"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

//go:embed mail_operators.yml
var mailOperatorsYamlForTest string

//go:embed mail_operators_gen.go
var mailOperatorsGenForTest string

//go:embed testdata/mail/labels.yml
var mailLabelsYamlForTest string

//go:embed mail_label.go
var mailLabelSourceForTest string

// The Go mail_operators_gen.go holds for list.
func mailOperatorsGenSource(list *MailOperatorList) ([]byte, error) {
	quoteList := func(values []string) string {
		quoted := []string{}
		for _, value := range values {
			quoted = append(quoted, strconv.Quote(value))
		}
		return "[]string{" + strings.Join(quoted, ", ") + "}"
	}
	var source strings.Builder
	source.WriteString("// Code generated from mail_operators.yml by TestMailOperatorsGenIsCurrent. DO NOT EDIT.\n\n")
	source.WriteString("package sidecar\n\n")
	source.WriteString("// mail_operators.yml's list, which this release embeds (D-MAIL-13). MailOperatorListEmbedded hands out copies.\n")
	fmt.Fprintf(&source, "var mailOperatorListEmbedded = &MailOperatorList{\n\tVersion: %d,\n\tOperators: []*MailOperator{\n", list.Version)
	for _, operator := range list.Operators {
		fmt.Fprintf(&source, "\t\t{\n\t\t\tId: %s,\n\t\t\tName: %s,\n\t\t\tPtrSuffixes: %s,\n\t\t\tDkimDomains: %s,\n\t\t\tDaneSource: %s,\n\t\t\tMtaStsSource: %s,\n\t\t},\n",
			strconv.Quote(operator.Id), strconv.Quote(operator.Name), quoteList(operator.PtrSuffixes), quoteList(operator.DkimDomains),
			strconv.Quote(operator.DaneSource), strconv.Quote(operator.MtaStsSource))
	}
	source.WriteString("\t},\n}\n")
	return format.Source([]byte(source.String()))
}

// mail_operators_gen.go is what mail_operators.yml generates, and the list compiled in is the file's; with
// SIDECAR_REGENERATE_MAIL_OPERATORS=1 this writes it instead.
func TestMailOperatorsGenIsCurrent(t *testing.T) {
	list, err := ParseMailOperatorList(mailOperatorsYamlForTest)
	if err != nil {
		t.Fatal(err)
	}
	generated, err := mailOperatorsGenSource(list)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("SIDECAR_REGENERATE_MAIL_OPERATORS") == "1" {
		if err := os.WriteFile("mail_operators_gen.go", generated, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if string(generated) != mailOperatorsGenForTest {
		t.Fatal("mail_operators_gen.go is stale; run go generate")
	}
	if !reflect.DeepEqual(MailOperatorListEmbedded(), list) {
		t.Fatal("the list compiled in is not the file's")
	}
	// a list with entries renders as Go too, each value quoted
	fixture, _ := mailLabelsFixture(t)
	if source, err := mailOperatorsGenSource(fixture); err != nil || !strings.Contains(string(source), `"https://dane-mail.example/security/dane"`) {
		t.Fatalf("%v", err)
	}
	// a copy, so a caller's change reaches no other
	copied := MailOperatorListEmbedded()
	copied.Version += 1
	if MailOperatorListEmbedded().Version == copied.Version {
		t.Fatal("the embedded list was changed through a copy")
	}
}

// labels.yml's fixture list parses, with its operators in the file's order.
func mailLabelsFixture(t *testing.T) (*MailOperatorList, []*mailYamlItem) {
	t.Helper()
	document, err := parseMailYamlSubset(mailLabelsYamlForTest)
	if err != nil {
		t.Fatal(err)
	}
	list, err := mailOperatorListOf(document)
	if err != nil {
		t.Fatal(err)
	}
	cases, ok := document.lists["cases"]
	if !ok || len(cases) == 0 {
		t.Fatal("labels.yml has no cases")
	}
	return list, cases
}

// The shape and rules ParseMailOperatorList holds a list to, each refusal naming its line.
func TestMailOperatorListRefusesWhatBreaksItsRules(t *testing.T) {
	list, _ := mailLabelsFixture(t)
	if list.Version != 7 || len(list.Operators) != 4 || list.Operators[1].Id != "sts-mail" || list.Operators[1].MtaStsSource == "" || list.Operators[1].DaneSource != "" {
		t.Fatalf("fixture %+v", list)
	}
	entry := func(lines ...string) string {
		return "version: 3\noperators:\n  - id: op-one\n    name: Op One\n" + strings.Join(lines, "\n") + "\n"
	}
	good := entry("    ptr_suffixes: [out.one.example]", "    dane: https://one.example/dane")
	if parsed, err := ParseMailOperatorList(good); err != nil || parsed.Version != 3 || parsed.Operators[0].PtrSuffixes[0] != "out.one.example" {
		t.Fatalf("%v, %v", parsed, err)
	}
	if parsed, err := ParseMailOperatorList("# none yet\nversion: 1\noperators: []\n"); err != nil || len(parsed.Operators) != 0 {
		t.Fatalf("%v, %v", parsed, err)
	}
	for name, text := range map[string]string{
		"no version":            "operators: []\n",
		"version zero":          "version: 0\noperators: []\n",
		"version not a number":  "version: v1\noperators: []\n",
		"no operators":          "version: 1\n",
		"another top key":       "version: 1\noperators: []\ncases: []\n",
		"a repeated top key":    "version: 1\nversion: 2\noperators: []\n",
		"no enforcement":        entry("    ptr_suffixes: [out.one.example]"),
		"no suffix or domain":   entry("    dane: https://one.example/dane"),
		"a one-label domain":    entry("    dkim_domains: [example]", "    dane: https://one.example/dane"),
		"an uppercase domain":   entry("    dkim_domains: [One.example]", "    dane: https://one.example/dane"),
		"a source over http":    entry("    dkim_domains: [one.example]", "    dane: http://one.example/dane"),
		"an unknown key":        entry("    dkim_domains: [one.example]", "    dane: https://one.example/dane", "    rank: 1"),
		"a repeated key":        entry("    dkim_domains: [one.example]", "    dkim_domains: [two.example]", "    dane: https://one.example/dane"),
		"a list for a scalar":   entry("    dkim_domains: [one.example]", "    dane: [https://one.example/dane]"),
		"a scalar for a list":   entry("    dkim_domains: one.example", "    dane: https://one.example/dane"),
		"a bad indent":          entry("   dkim_domains: [one.example]", "    dane: https://one.example/dane"),
		"a tab":                 entry("    dkim_domains:\t[one.example]", "    dane: https://one.example/dane"),
		"an inline comment":     entry("    dkim_domains: [one.example]", "    dane: https://one.example/dane #x"),
		"an unclosed quote":     entry("    dkim_domains: [one.example]", `    dane: "https://one.example/dane`),
		"a name claiming paths": strings.Replace(entry("    dkim_domains: [one.example]", "    dane: https://one.example/dane"), "Op One", "End-to-End Mail", 1),
		"a repeated id": entry("    dkim_domains: [one.example]", "    dane: https://one.example/dane") +
			"  - id: op-one\n    name: Op Two\n    dkim_domains: [two.example]\n    dane: https://two.example/dane\n",
		"a bad id": strings.Replace(entry("    dkim_domains: [one.example]", "    dane: https://one.example/dane"), "op-one", "Op_One", 1),
	} {
		if _, err := ParseMailOperatorList(text); !errors.Is(err, ErrMailOperatorListInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// One labels.yml case as a deposit and label input.
type mailLabelCase struct {
	name   string
	input  *MailLabelInput
	values map[string]mailYamlValue
}

// The receiver labels.yml's deposits name.
var mailLabelReceiverForTest = []byte{0x01, 0x92, 0x5a, 0x7e, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x2a}

// The hash labels.yml's messages have.
var mailLabelMessageSha256ForTest = func() []byte {
	hash := make([]byte, 32)
	hash[0] = 0xab
	return hash
}()

// A case's deposit and input, as its keys give them.
func mailLabelCaseOf(t *testing.T, item *mailYamlItem, list *MailOperatorList) *mailLabelCase {
	t.Helper()
	scalar := func(key string, otherwise string) string {
		if value, ok := item.values[key]; ok {
			return value.scalar
		}
		return otherwise
	}
	flag := func(key string) bool {
		return scalar(key, "false") == "true"
	}
	c := &mailLabelCase{name: scalar("name", ""), values: item.values}
	for _, key := range item.keys {
		switch key {
		case "name", "deposit", "evidence", "require_tls", "tlsa", "ptr", "dkim", "from", "recipients", "mta_sts", "limits", "strict_chain",
			"may_send", "list", "want", "want_rule", "want_operator", "want_match", "want_cites", "want_unavailable", "want_incomplete", "want_strict":
		default:
			t.Fatalf("%s: a key %q", c.name, key)
		}
	}
	recipients := []string{"id@acme.root.example"}
	if value, ok := item.values["recipients"]; ok {
		recipients = value.list
	}
	evidence := &protocol.MailAuthEvidence{
		Version:           1,
		MessageSha256:     mailLabelMessageSha256ForTest,
		ReceiveTimeMillis: 1793923200000,
		ReceiverSidecarId: mailLabelReceiverForTest,
		SniTlsaLive:       flag("tlsa"),
		PtrName:           scalar("ptr", ""),
		StrictChain:       flag("strict_chain"),
		Arc:               &protocol.ArcResult{Cv: protocol.ArcVerdict_ARC_NONE},
	}
	if value, ok := item.values["dkim"]; ok {
		verdicts := map[string]protocol.DkimVerdict{
			"pass": protocol.DkimVerdict_DKIM_PASS, "fail": protocol.DkimVerdict_DKIM_FAIL, "permerror": protocol.DkimVerdict_DKIM_PERMERROR,
			"temperror": protocol.DkimVerdict_DKIM_TEMPERROR, "incomplete": protocol.DkimVerdict_DKIM_INCOMPLETE,
		}
		for _, entry := range value.list {
			domain, verdict, _ := strings.Cut(entry, "=")
			if _, ok := verdicts[verdict]; !ok {
				t.Fatalf("%s: a verdict %q", c.name, verdict)
			}
			evidence.Dkim = append(evidence.Dkim, &protocol.DkimResult{Domain: domain, Selector: "s1", Result: verdicts[verdict]})
		}
	}
	if flag("limits") {
		evidence.Limits = &protocol.AuthLimits{Reason: MailAuthLimitDeadline}
	}
	switch scalar("evidence", "sealed") {
	case "sealed":
	case "none":
		evidence = nil
	case "version-2":
		evidence.Version = 2
	case "other-receiver":
		evidence.ReceiverSidecarId = []byte{0x02}
	case "other-message":
		evidence.MessageSha256 = make([]byte, 32)
	default:
		t.Fatalf("%s: evidence %q", c.name, scalar("evidence", ""))
	}
	deposit := &protocol.MailDeposit{
		Version:           1,
		Evidence:          evidence,
		MailFrom:          []byte("bounce@sender.example"),
		RequireTls:        flag("require_tls"),
		Recipients:        recipients,
		ReceiverSidecarId: mailLabelReceiverForTest,
	}
	switch scalar("deposit", "receiver") {
	case "receiver":
	case "same-network":
		deposit = &protocol.MailDeposit{Version: 1, MailFrom: []byte("member@acme.root.example"), Recipients: recipients, RequireTls: flag("require_tls")}
	case "none":
		deposit = nil
	default:
		t.Fatalf("%s: deposit %q", c.name, scalar("deposit", ""))
	}
	c.input = &MailLabelInput{
		Deposit:             deposit,
		MessageSha256:       mailLabelMessageSha256ForTest,
		FromDomain:          scalar("from", ""),
		Root:                "root.example",
		RecipientMtaSts:     flag("mta_sts"),
		SignerMaySendAsFrom: flag("may_send"),
		Operators:           list,
	}
	if scalar("list", "fixture") == "empty" {
		c.input.Operators = &MailOperatorList{Version: 9, Operators: []*MailOperator{}}
	}
	return c
}

// Every labels.yml case labels as it says, its basis, citations and marks included, and its statement says what the
// rule is with no path claim; each result builds an i/ row.
func TestMailLabelVectors(t *testing.T) {
	list, items := mailLabelsFixture(t)
	labels := map[string]protocol.MailTlsLabel{
		"validated": protocol.MailTlsLabel_MAIL_TLS_VALIDATED, "opportunistic": protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC,
		"member-signed": protocol.MailTlsLabel_MAIL_TLS_MEMBER_SIGNED,
	}
	rules := map[string]protocol.MailTlsRule{
		"none": protocol.MailTlsRule_MAIL_TLS_RULE_UNSPECIFIED, "requiretls": protocol.MailTlsRule_MAIL_TLS_RULE_REQUIRETLS,
		"operator": protocol.MailTlsRule_MAIL_TLS_RULE_OPERATOR,
	}
	matches := map[string]MailLabelMatch{"": MailLabelMatchNone, "ptr": MailLabelMatchPtr, "dkim": MailLabelMatchDkim}
	for _, item := range items {
		c := mailLabelCaseOf(t, item, list)
		want := func(key string) string {
			return c.values[key].scalar
		}
		result := MailLabelDecide(c.input)
		wantLabel, ok := labels[want("want")]
		if !ok {
			t.Fatalf("%s: want %q", c.name, want("want"))
		}
		wantRule := rules["none"]
		if want("want_rule") != "" {
			wantRule = rules[want("want_rule")]
		}
		if result.Label != wantLabel || result.Basis.GetRule() != wantRule || result.Basis.GetOperatorId() != want("want_operator") ||
			result.MatchedBy != matches[want("want_match")] {
			t.Errorf("%s: %v %v %q match %d", c.name, result.Label, result.Basis.GetRule(), result.Basis.GetOperatorId(), result.MatchedBy)
		}
		cites := map[[2]bool]string{{false, false}: "", {true, false}: "dane", {false, true}: "mta-sts", {true, true}: "both"}[[2]bool{result.CitesDane, result.CitesMtaSts}]
		if wantCites := strings.TrimPrefix(want("want_cites"), "none"); cites != wantCites {
			t.Errorf("%s: cites %q", c.name, cites)
		}
		if result.EvidenceUnavailable != (want("want_unavailable") == "true") || result.ChecksIncomplete != (want("want_incomplete") == "true") ||
			result.Basis.GetStrictCustomMx() != (want("want_strict") == "true") {
			t.Errorf("%s: unavailable %t, incomplete %t, strict %t", c.name, result.EvidenceUnavailable, result.ChecksIncomplete, result.Basis.GetStrictCustomMx())
		}
		// a basis on every label a receiver's evidence decided, with the list's version, and on no other
		if (result.Basis != nil) != (c.input.Deposit != nil && mailReceiverDeposit(c.input.Deposit) && !result.EvidenceUnavailable) ||
			(result.Basis != nil && result.Basis.GetListVersion() != c.input.Operators.Version) {
			t.Errorf("%s: basis %v", c.name, result.Basis)
		}
		statement := result.Statement()
		mailLabelStatementClaimsNoPath(t, c.name, statement)
		if wantRule == protocol.MailTlsRule_MAIL_TLS_RULE_OPERATOR && !strings.Contains(statement, "inference from the operator's listing, not proof") {
			t.Errorf("%s: an operator's basis states no inference: %q", c.name, statement)
		}
		if wantRule == protocol.MailTlsRule_MAIL_TLS_RULE_REQUIRETLS && !strings.Contains(statement, "only the final hop's requirement") {
			t.Errorf("%s: REQUIRETLS states more than the final hop: %q", c.name, statement)
		}
		if strings.Contains(statement, "evidence unavailable") != result.EvidenceUnavailable || strings.Contains(statement, "Checks incomplete") != result.ChecksIncomplete {
			t.Errorf("%s: %q", c.name, statement)
		}
		// MTA-STS is named only where cited, so never for a burner, and DANE enforcement only where cited
		if strings.Contains(statement, "MTA-STS") != result.CitesMtaSts || strings.Contains(statement, "publishes its DANE") != result.CitesDane {
			t.Errorf("%s: cites dane %t, mta-sts %t, says %q", c.name, result.CitesDane, result.CitesMtaSts, statement)
		}
		// the i/ row takes every label the decision gives
		if c.input.Deposit != nil && 0 < len(c.input.Deposit.GetRecipients()) {
			if _, err := MailBuildIndexEntry(&MailIndexEntryInput{
				Id: Id{0x01}, Deposit: c.input.Deposit, Parsed: &MailParsed{}, TlsLabel: result.Label, TlsBasis: result.Basis,
			}); err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
		}
	}
}

// No label string claims end-to-end delivery or a confidential path: the statement given, and every literal the
// label's own source holds.
func mailLabelStatementClaimsNoPath(t *testing.T, name string, statement string) {
	t.Helper()
	folded := strings.ToLower(statement)
	for _, claim := range []string{"end-to-end", "end to end", "confidential", "unread", "secure path", "encrypted all the way"} {
		if strings.Contains(folded, claim) {
			t.Errorf("%s: %q claims %q", name, statement, claim)
		}
	}
}

// The text scan: mail_label.go holds no "end-to-end" or "end to end" anywhere, so no label string it builds can.
func TestMailLabelStringsClaimNoEndToEnd(t *testing.T) {
	folded := strings.ToLower(mailLabelSourceForTest)
	if strings.Contains(folded, "end-to-end") || strings.Contains(folded, "end to end") {
		t.Fatal("mail_label.go holds an end-to-end claim")
	}
}

// FS-121: no incomplete evidence validates. With the TLSA live, a listed operator's aligned DKIM domain and every
// verdict but pass, under limits or not, the label is opportunistic, and what a bound cut never counts.
func TestMailLabelIncompleteEvidenceNeverValidates(t *testing.T) {
	list, _ := mailLabelsFixture(t)
	for _, verdict := range []protocol.DkimVerdict{
		protocol.DkimVerdict_DKIM_VERDICT_UNSPECIFIED, protocol.DkimVerdict_DKIM_FAIL, protocol.DkimVerdict_DKIM_PERMERROR,
		protocol.DkimVerdict_DKIM_TEMPERROR, protocol.DkimVerdict_DKIM_INCOMPLETE,
	} {
		for _, limited := range []bool{false, true} {
			evidence := &protocol.MailAuthEvidence{
				Version: 1, MessageSha256: mailLabelMessageSha256ForTest, ReceiverSidecarId: mailLabelReceiverForTest, SniTlsaLive: true,
				Dkim:  []*protocol.DkimResult{{Domain: "dane-mail.example", Selector: "s1", Result: verdict}},
				Spf:   &protocol.SpfResult{Result: protocol.SpfVerdict_SPF_PASS, Domain: "dane-mail.example"},
				Dmarc: &protocol.DmarcResult{Result: protocol.DmarcVerdict_DMARC_PASS},
			}
			if limited {
				evidence.Limits = &protocol.AuthLimits{Reason: MailAuthLimitCount | MailAuthLimitDeadline}
			}
			result := MailLabelDecide(&MailLabelInput{
				Deposit:       &protocol.MailDeposit{Version: 1, Evidence: evidence, Recipients: []string{"id@acme.root.example"}, ReceiverSidecarId: mailLabelReceiverForTest},
				MessageSha256: mailLabelMessageSha256ForTest,
				FromDomain:    "dane-mail.example",
				Root:          "root.example",
				Operators:     list,
			})
			if result.Label != protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC || result.ChecksIncomplete != limited {
				t.Errorf("%v, limited %t: %v", verdict, limited, result.Label)
			}
		}
	}
}

// FS-39's delayed DNS: a message labeled opportunistic at reception, its TLSA not yet live, keeps that label when a
// later check, with the TLSA live then, would validate it; the recheck says so apart and changes nothing. The other
// way too: a validated label stands when the operator later leaves the list.
func TestMailLabelLaterDnsLeavesTheReceptionLabel(t *testing.T) {
	list, _ := mailLabelsFixture(t)
	evidence := &protocol.MailAuthEvidence{
		Version: 1, MessageSha256: mailLabelMessageSha256ForTest, ReceiverSidecarId: mailLabelReceiverForTest, PtrName: "a1.out.dane-mail.example",
	}
	input := &MailLabelInput{
		Deposit:       &protocol.MailDeposit{Version: 1, Evidence: evidence, Recipients: []string{"id@acme.root.example"}, ReceiverSidecarId: mailLabelReceiverForTest},
		MessageSha256: mailLabelMessageSha256ForTest,
		Root:          "root.example",
		Operators:     list,
	}
	atReception := MailLabelDecide(input)
	entry := &protocol.IndexEntry{TlsLabel: atReception.Label, TlsBasis: atReception.Basis}
	stored := proto.CloneOf(entry)
	later := *input
	later.Deposit = proto.CloneOf(input.Deposit)
	later.Deposit.Evidence.SniTlsaLive = true
	recheck := MailLabelRecheck(entry.GetTlsLabel(), entry.GetTlsBasis(), &later)
	if atReception.Label != protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC || recheck.Label != protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC ||
		recheck.Later.Label != protocol.MailTlsLabel_MAIL_TLS_VALIDATED || !recheck.Differs {
		t.Errorf("reception %v, recheck %v later %v differs %t", atReception.Label, recheck.Label, recheck.Later.Label, recheck.Differs)
	}
	if !proto.Equal(entry, stored) || !proto.Equal(recheck.Basis, stored.GetTlsBasis()) {
		t.Error("the recheck changed the stored label")
	}
	if statement := recheck.Statement(); !strings.Contains(statement, "would label this message validated") || !strings.Contains(statement, "it stands") {
		t.Errorf("%q", statement)
	}
	// a validated label stands when the operator later leaves the list
	input.Deposit.Evidence.SniTlsaLive = true
	validated := MailLabelDecide(input)
	newer := *input
	newer.Operators = &MailOperatorList{Version: 8, Operators: list.Operators[1:2]}
	recheck = MailLabelRecheck(validated.Label, validated.Basis, &newer)
	if recheck.Label != protocol.MailTlsLabel_MAIL_TLS_VALIDATED || recheck.Basis.GetOperatorId() != "dane-mail" || recheck.Basis.GetListVersion() != 7 ||
		recheck.Later.Label != protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC || !recheck.Differs {
		t.Errorf("recheck %v %v, later %v", recheck.Label, recheck.Basis, recheck.Later.Label)
	}
	// the same evidence and list agree
	if again := MailLabelRecheck(validated.Label, validated.Basis, input); again.Differs || !strings.Contains(again.Statement(), "agrees") {
		t.Errorf("%q", again.Statement())
	}
}

// FS-39's second hop: a fixture whose first hop read the message, kept its DKIM signature and added REQUIRETLS for the
// last hop is validated by REQUIRETLS as stated, its statement naming only the final hop, with no exact path claim.
func TestMailLabelRequireTlsFromASecondHopClaimsNoPath(t *testing.T) {
	list, _ := mailLabelsFixture(t)
	evidence := &protocol.MailAuthEvidence{
		Version: 1, MessageSha256: mailLabelMessageSha256ForTest, ReceiverSidecarId: mailLabelReceiverForTest,
		Dkim: []*protocol.DkimResult{{Domain: "origin.example", Selector: "s1", Result: protocol.DkimVerdict_DKIM_PASS}},
	}
	result := MailLabelDecide(&MailLabelInput{
		Deposit: &protocol.MailDeposit{
			Version: 1, Evidence: evidence, RequireTls: true, Recipients: []string{"id@acme.root.example"}, ReceiverSidecarId: mailLabelReceiverForTest,
		},
		MessageSha256: mailLabelMessageSha256ForTest,
		FromDomain:    "origin.example",
		Root:          "root.example",
		Operators:     list,
	})
	statement := result.Statement()
	if result.Label != protocol.MailTlsLabel_MAIL_TLS_VALIDATED || result.Basis.GetRule() != protocol.MailTlsRule_MAIL_TLS_RULE_REQUIRETLS ||
		!strings.Contains(statement, "only the final hop's requirement") || !strings.Contains(statement, "URnetwork included") {
		t.Errorf("%v: %q", result.Label, statement)
	}
	mailLabelStatementClaimsNoPath(t, "second hop", statement)
}

// A stored label stated at read time: its operator named from the list, its enforcement cited only from the list
// version it was decided against, never MTA-STS for a burner, and the marks its auth results carry.
func TestMailLabelOfEntry(t *testing.T) {
	list, _ := mailLabelsFixture(t)
	entry := &protocol.IndexEntry{
		TlsLabel:    protocol.MailTlsLabel_MAIL_TLS_VALIDATED,
		TlsBasis:    &protocol.MailTlsBasis{Rule: protocol.MailTlsRule_MAIL_TLS_RULE_OPERATOR, OperatorId: "both-mail", ListVersion: 7},
		AuthResults: &protocol.MailAuthResults{ChecksIncomplete: true},
	}
	stated := MailLabelOfEntry(entry, list, false, true)
	if !stated.CitesDane || !stated.CitesMtaSts || !stated.ChecksIncomplete || stated.Operator == nil || stated.Operator.Name != "Both Mail" {
		t.Errorf("%+v", stated)
	}
	if burner := MailLabelOfEntry(entry, list, true, true); !burner.CitesDane || burner.CitesMtaSts || strings.Contains(burner.Statement(), "MTA-STS") {
		t.Errorf("burner %+v", burner)
	}
	newer := &MailOperatorList{Version: 8, Operators: list.Operators}
	if later := MailLabelOfEntry(entry, newer, false, true); later.CitesDane || later.CitesMtaSts || !strings.Contains(later.Statement(), "Both Mail") {
		t.Errorf("another version %+v", later)
	}
	gone := MailLabelOfEntry(entry, &MailOperatorList{Version: 7}, false, true)
	if gone.Operator != nil || !strings.Contains(gone.Statement(), "both-mail") {
		t.Errorf("unlisted %q", gone.Statement())
	}
	// the embedded list has no such operator, and its version is not 7
	if embedded := MailLabelOfEntry(entry, nil, false, true); embedded.CitesDane || embedded.CitesMtaSts {
		t.Errorf("embedded %+v", embedded)
	}
}
