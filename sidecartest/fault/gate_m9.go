// M9's reviews (TEST-M9-01; §23.6's M9 row, §23.4's M9 exit, §22.10's smtpproof/SPEC.md row, §23.8's freezes; D-TEST-9,
// R-TEST-7, D-SMTP-16, FS-31, FS-42, FS-55, FS-123): the sweep `sidecar-gate M9` reports, row by row and item by item,
// pass, fail, missing or open, and the items its entry review, `sidecar-gate M9-in`, reads beside the assembly check.
// Like every sweep before it (gate_m5.go, gate_m8.go) it adds no mechanism: each row runs the tests its owners wrote,
// and a failure or a missing test goes back to the task that owns it and stays in the report until fixed.
//
// None of M9's rows has a registered builder. Each is named by the tests its owners wrote for it, where they run, with
// that package's tags (owner decision 548; QD-1081):
//
//   - FS-31 runs in smtpproof, a module of its own (§4.4), in its two legs: the plain one, where edgeSession takes each
//     part with the part's circuit solved on gnark's solver beside the relation, and sidecar_testhooks, where the real
//     engine verifies through smtpproof's Verifier (SMTP-M9-30's matrix, smtpproof/testdata/fs31/matrix.md). On T3,
//     server's smtpedgehost reruns the rows a crypto/tls ScriptedMx serves and whose sender acts on the wire alone; the
//     rows that change a witness run at T2 alone, as SMTP-M9-30 reads them.
//   - FS-123 runs on SmtpSendWorld's stub edge in sidecartest (SMTP-M9-31), MAIL's side through MailClient on M9World
//     (MAIL-M9-06), the root's CheckSend, SendResult and send watch with the daemon's backends over them (QD-1122), and
//     the sdk's bound half (SDK-M9-01); on T3 in server's smtpedgehost on the block's engine over the private stores.
//   - FS-42's M9 step runs on T3 alone in server's model: a sending sidecar revoked after the dump has no DKIM selector on
//     either NS once api's replay ends (SMTP-M9-19), through DNS-M9-01's delete in the caller's transaction.
//
// §22.10's evidence for smtpproof/SPEC.md: its specification at the entry review, the relation with E1-E3 and Z1-Z9
// named, each with its section, test and mutation (SMTP-M9-33); at the exit, each mutated witness listed with what
// refused it, one item a check, whose listing a command holds to SMTP-M9-29's evidence table, so the report never shows
// a witness the suite no longer has; the checker written apart (SMTP-M9-28), which reads open on people, since its
// author is no outsider to the circuits; FS-31's scripted MXs, as the row runs them; the vectors the exit freezes; and
// what this host cannot show: two non-authors' written argument, D-SMTP-16's p95 on its two machines, coverage on the
// census MXs and interop at the providers (§22.9's ZK and MTA rows). The trap is an item of its own: burner email
// launches receive-only if the proofs miss D-SMTP-16 (owner decisions 9, 35), so a miss is the owner's to hear, and a
// smoke run on this host stands for none of those rows.
//
// S6 and S10 are §22.7's scenarios at M9, read part by part and tier by tier from the scenario registry as M10's sweep
// reads S11 and S12 (gateScenarioItems), so a part no test is registered to reads missing, never pass, and T6 reads
// open. S6's tests run outside RunScenario on SmtpSendWorld and M9World, so they are named in an item of their own, and
// S6's registry items read missing until SMTP-M9-31 registers it.
//
// Beside them: §22.8's rules and FI bindings, and FI-11's and FI-12's oracles, which none of M9's rows feeds yet; §23.4's
// exit criteria, DANE-only MXs reached and unauthenticated ones refused, and halt, ARF and RUA joins; §14's privacy rows
// and the schema guard at M9; the preamble's inline path and the CROSSSLOT lint; smtpedge's load harness; and what the
// world owes: HE's TCP 25, the hardware runs, the census and the providers. FS-55 is the every gate's, which the tool
// runs at M9's exit with MG9, §14's remaining smtp_* tables (§19.7).

package fault

import (
	"fmt"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The catalog's names for M9's entry and exit.
const (
	gateM9InGate  = "M9-in"
	gateM9OutGate = "M9-out"
)

// The tags server's smtpedgehost builds its T3 rows under: the pending migration groups, MG9's smtp_* among them, and
// the hooks, which hand the block its streams and smtpproof's relation key set.
const gateM9SmtpEdgeTags = "sidecar_pending,sidecar_testhooks"

// The cases of M9 that pass on their owners' tests alone, with no registered builder, in the catalog's order.
var gateM9ClauseRows = []string{"FS-31", "FS-42's m9", "FS-123"}

// Tests of the smtpproof module, which sits in this repo beside the root module (§4.4), in the leg tags names.
func gateSmtpproofTests(packagePath string, tags string, names ...string) *GateTest {
	return &GateTest{Repo: "sidecar", Dir: "smtpproof", Package: packagePath, Tags: tags, Names: names}
}

// FS-31's rows in smtpproof's plain leg, where each part's circuit is solved beside the relation, with the matrix's
// evidence table, the transcript oracle's own check and FuzzSmtpTranscript's seeds.
var gateFs31PlainTests = gateSmtpproofTests(".", "",
	"TestFs31HonestControls", "TestFs31ScriptedMxs", "TestFs31MaliciousSender", "TestFs31PartsBoundToOneKeyPart", "TestFs31BdatBodyRecords",
	"TestFs31MaliciousEdge", "TestFs31MatrixTable", "TestFs31TranscriptOracleSeesARecordTheSenderDidNotWrite", "FuzzSmtpTranscript",
)

// FS-31's rows in smtpproof's sidecar_testhooks leg, through the real engine, and the edge forging 250 and EHLO replies
// to a sender that keeps its message.
var gateFs31EngineTests = gateSmtpproofTests(".", "sidecar_testhooks",
	"TestFs31HonestControls", "TestFs31ScriptedMxs", "TestFs31MaliciousSender", "TestFs31PartsBoundToOneKeyPart", "TestFs31BdatBodyRecords",
	"TestFs31MaliciousEdge", "TestFs31TheSenderKeepsAMessageTheEdgeForgedSent",
)

// FS-31 on T3: the rows server's smtpedgehost reruns on the block's engine over the private stores.
var gateFs31T3Tests = &GateTest{Repo: "server", Package: "./smtpedgehost", Tags: gateM9SmtpEdgeTags, Stores: true, Names: []string{
	"TestT3Fs31AnHonestSend", "TestT3Fs31AnHonestSendTo100Recipients", "TestT3Fs31AnHonestSendWithA16KibHeaderBlock", "TestT3Fs31NoChunking",
	"TestT3Fs31ChunkingOnlyBeforeTls", "TestT3Fs31NoPipelining", "TestT3Fs31MailRefused", "TestT3Fs31RcptRefused", "TestT3Fs31MixedRecipients",
	"TestT3Fs31No354", "TestT3Fs31A451", "TestT3Fs31ASecondTransactionInTheBdatBody", "TestT3Fs31ReplyCountOneFewer", "TestT3Fs31ReplyCountOneMore",
	"TestT3Fs31AMessageRecordBeforeTheEnvelopesReplies",
}}

// S6's rows on T3, on the block's engine over the private stores (SMTP-M9-31).
var gateS6T3Tests = &GateTest{Repo: "server", Package: "./smtpedgehost", Tags: gateM9SmtpEdgeTags, Stores: true, Names: []string{
	"TestT3S6NoRecordReachesTheMxBeforeItsPart", "TestT3S6NoUnauthenticatedMx", "TestT3S6TooLargeForTheNonChunkingDomainAlone",
}}

// Where M9's cases run their tests outside the convention: see the file header.
func gateM9Cases(catalog *Catalog) map[string][]*GateTest {
	caseOf := func(rowId string, caseName string) *Case {
		return gateCaseOf(catalog, rowId, caseName)
	}
	cases := map[string][]*GateTest{}

	cases[caseOf("FS-31", "").String()] = []*GateTest{gateFs31PlainTests, gateFs31EngineTests, gateFs31T3Tests}

	cases[caseOf("FS-123", "").String()] = []*GateTest{
		{Repo: "sidecar", Package: "./sidecartest", Names: []string{
			"TestFs123SentFromADesktop", "TestFs123QueuedFromAPhone", "TestFs123OtherOutcomesReachTheResult", "TestFs123RunnerNamesTheSendItsEntryNames",
		}},
		{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_testhooks", Names: []string{
			"TestFs123MailOutcomesStandInTheSendingMailbox", "TestFs123CoverageCopySaysNothingOfSending",
		}},
		gateSidecarTests(
			"TestMailCheckSendHandsTheBoundSenderTheMessageSendWouldMake", "TestMailCheckSendWithNoSenderPricesOnTheMembersProverRecords",
			"TestMailSendResultReadsASendByItsId", "TestMailSendWatchRaisesOncePerChangedOutcome", "TestDaemonMailCheckSendAnswersADraftsDomains",
			"TestDaemonMailSendResultAnswersAKnownSendAndRefusesAnUnknownId",
		),
		{Repo: "sdk", Package: ".", Names: []string{"TestCheckSendPredictsPerDomain", "TestSendResultsReachGetSendResultAndMailSend", "TestSendCopyNamesNoIndexer"}},
		{Repo: "server", Package: "./smtpedgehost", Tags: gateM9SmtpEdgeTags, Stores: true, Names: []string{
			"TestT3Fs123SentFromADesktop", "TestT3Fs123QueuedFromAPhone", "TestT3Fs123OtherOutcomesReachTheResult",
		}},
	}

	// FS-42's M9 step: a sending sidecar revoked after the dump has no DKIM selector once api's replay ends, the
	// removal taking its selectors in its own write, the delete in the caller's transaction leaving both NS without one
	cases[caseOf("FS-42", "m9").String()] = []*GateTest{
		gatePendingTests("./model",
			"TestSmtpDkimRevokedAfterTheDumpHasNoSelectorOnceTheReplayEnds", "TestSmtpDkimRemovalDeletesSelectorsInItsOwnWrite",
			"TestDnsDkimDeleteInTheCallersTransaction",
		),
	}
	return cases
}

// The TLS legs §22.10's mutated witnesses run in, as smtpproof's evidence table names them, and its two modes.
const (
	gateWitnessLegAes    = "1.3 AES-128-GCM"
	gateWitnessLegChacha = "1.3 ChaCha20-Poly1305"
	gateWitnessLegEcdsa  = "1.2 ECDHE-ECDSA AES-128-GCM"
	gateWitnessModeBdat  = "BDAT"
	gateWitnessModeData  = "DATA"
)

// What refuses an E break: edgeSession on its own, as the table writes it.
const gateWitnessRefusedAtGate = "gate"

// One of §22.10's mutated witnesses as M9's exit lists it (SMTP-M9-29): the check that alone refuses it, its break,
// what refused it, as smtpproof/testdata/mutations/table.md writes each, and the TLS legs and modes it runs in.
type gateMutatedWitness struct {
	check     string
	mutation  string
	refusedAt string
	legs      []string
	modes     []string
}

// A cell no witness can break alone, as the table lists it: a check, a TLS version and a mode.
type gateWitnessExcusedCell struct {
	check   string
	version string
	mode    string
}

// Every check §22.10 asks a mutated witness for, in SPEC.md's order.
var gateWitnessChecks = []string{"E1", "E2", "E3", "Z1", "Z2", "Z3", "Z4", "Z5", "Z6", "Z7", "Z8", "Z9"}

// The witnesses M9's exit lists, in the evidence table's order. gateM9WitnessesListed holds them to the table.
func gateM9Witnesses() []*gateMutatedWitness {
	every := []string{gateWitnessLegAes, gateWitnessLegChacha, gateWitnessLegEcdsa}
	tls13 := []string{gateWitnessLegAes, gateWitnessLegChacha}
	tls12 := []string{gateWitnessLegEcdsa}
	both := []string{gateWitnessModeBdat, gateWitnessModeData}
	bdat := []string{gateWitnessModeBdat}
	data := []string{gateWitnessModeData}
	return []*gateMutatedWitness{
		{check: "E1", mutation: "a client record of another type after the handshake", refusedAt: gateWitnessRefusedAtGate, legs: every, modes: both},
		{check: "E1", mutation: "a server record of type handshake after the handshake, renegotiation in 1.2", refusedAt: gateWitnessRefusedAtGate, legs: every, modes: both},
		{check: "E2", mutation: "a disclosed SHTS one bit off", refusedAt: gateWitnessRefusedAtGate, legs: tls13, modes: both},
		{check: "E2", mutation: "a ServerKeyExchange whose signature is one bit off", refusedAt: gateWitnessRefusedAtGate, legs: tls12, modes: both},
		{check: "E3", mutation: "a record one bit off the ciphertext its part proved", refusedAt: gateWitnessRefusedAtGate, legs: every, modes: both},
		{check: "E3", mutation: "a part's record of another outer type, which the circuit cannot see", refusedAt: gateWitnessRefusedAtGate, legs: every, modes: both},
		{check: "E3", mutation: "a part opening one record more, which its position gives a role the part cannot open", refusedAt: gateWitnessRefusedAtGate, legs: every, modes: both},
		{check: "E3", mutation: "the msg part covers none of the envelope's replies, its own count of them 0, so only the EHLO reply is proven", refusedAt: gateWitnessRefusedAtGate, legs: every, modes: both},
		{check: "Z1", mutation: "another HS or master secret, the keys it gave kept", refusedAt: "part 1 (key), on its production shape", legs: every, modes: both},
		{check: "Z1", mutation: "the env part's client key one bit off, its records sealed again under that key", refusedAt: "part 2 (env)", legs: every, modes: both},
		{check: "Z2", mutation: "a MAIL record whose first ciphertext octet no longer opens to the claimed M", refusedAt: "part 2 (env)", legs: every, modes: both},
		{check: "Z3", mutation: "the msg part's first record sealed with inner type 22 under the true key", refusedAt: "part 3 (msg)", legs: tls13, modes: both},
		{check: "Z4", mutation: "a command of its template's length that says another: BDAT's count, or DATB", refusedAt: "part 3 (msg)", legs: every, modes: bdat},
		{check: "Z4", mutation: "a command of its template's length that says another: BDAT's count, or DATB", refusedAt: "part 2 (env)", legs: every, modes: data},
		{check: "Z5", mutation: "a header block whose Feedback-ID field is renamed, so it has none", refusedAt: "part 3 (msg)", legs: every, modes: both},
		{check: "Z5", mutation: "header record 2 scanned from the start state, where record 1 ended inside a field's name", refusedAt: "part 4 (hdr)", legs: every, modes: both},
		{check: "Z6", mutation: "QUIX in QUIT's place at last_record", refusedAt: "part 3 (msg)", legs: every, modes: bdat},
		{check: "Z6", mutation: "a body record ending the message early, as long as its honest twin", refusedAt: "part 4 (body)", legs: every, modes: data},
		{check: "Z6", mutation: "body record 2 scanned from the start state, where record 1 ended inside a line", refusedAt: "part 5 (body)", legs: every, modes: data},
		{check: "Z7", mutation: "an RCPT reply's record replaced by a server KeyUpdate", refusedAt: "part 3 (msg)", legs: tls13, modes: both},
		{check: "Z8", mutation: "an RCPT reply refused, 550 in 250's place", refusedAt: "part 3 (msg)", legs: every, modes: both},
		{check: "Z8", mutation: "reply_count one fewer than the records hold: the first RCPT's reply rewritten as two replies, in its length", refusedAt: "part 3 (msg)", legs: every, modes: both},
		{check: "Z8", mutation: "reply_count one more than the records hold: MAIL's reply continued into the first RCPT's, in its length", refusedAt: "part 3 (msg)", legs: every, modes: both},
		{check: "Z8", mutation: "an env part's own reply_count one fewer on the wire than its records hold, the envelope one command a group", refusedAt: "part 3 (env)", legs: every, modes: both},
		{check: "Z9", mutation: "an EHLO reply whose CHUNKING line is misspelled CHUNKINX", refusedAt: "part 2 (env)", legs: every, modes: bdat},
	}
}

// The cells M9's exit says no witness can break alone, each with its reason in the table: 1.2's Z3 and Z7, whose
// values are public there, and DATA's Z9, which has no condition.
func gateM9WitnessExcusedCells() []*gateWitnessExcusedCell {
	return []*gateWitnessExcusedCell{
		{check: "Z3", version: "1.2", mode: gateWitnessModeBdat},
		{check: "Z3", version: "1.2", mode: gateWitnessModeData},
		{check: "Z7", version: "1.2", mode: gateWitnessModeBdat},
		{check: "Z7", version: "1.2", mode: gateWitnessModeData},
		{check: "Z9", version: "1.3", mode: gateWitnessModeData},
		{check: "Z9", version: "1.2", mode: gateWitnessModeData},
	}
}

// Where a witness runs, in words: every leg, TLS 1.3's two or TLS 1.2's, then the modes.
func gateWitnessCellsText(witness *gateMutatedWitness) string {
	legs := strings.Join(witness.legs, ", ")
	switch {
	case slices.Equal(witness.legs, []string{gateWitnessLegAes, gateWitnessLegChacha, gateWitnessLegEcdsa}):
		legs = "every TLS leg"
	case slices.Equal(witness.legs, []string{gateWitnessLegAes, gateWitnessLegChacha}):
		legs = "TLS 1.3's two legs"
	case slices.Equal(witness.legs, []string{gateWitnessLegEcdsa}):
		legs = "TLS 1.2's leg"
	}
	return legs + ", " + strings.Join(witness.modes, " and ")
}

// One item per check of §22.10's mutated witnesses, in SPEC.md's order, each listing its witnesses with what refused
// them, and the cells no witness can break alone, and running the check's own test in smtpproof's plain leg, where
// each Z break's circuit is solved, beside the table's and the honest twins' tests.
func gateM9WitnessItems() []*GateItem {
	shared := gateSmtpproofTests(".", "", "TestMutatedWitnessHonestTwins", "TestMutatedWitnessTable")
	items := []*GateItem{}
	for _, check := range gateWitnessChecks {
		breaks := []string{}
		for _, witness := range gateM9Witnesses() {
			if witness.check != check {
				continue
			}
			refused := "refused at " + witness.refusedAt
			if witness.refusedAt == gateWitnessRefusedAtGate {
				refused = "refused at the gate, by edgeSession on its own before any circuit is asked"
			}
			breaks = append(breaks, fmt.Sprintf("%s, %s, in %s", witness.mutation, refused, gateWitnessCellsText(witness)))
		}
		text := fmt.Sprintf("§22.10's mutated witnesses for %s, each refused by %s alone, the gate's relationCheckPart and smtpproof/checker each naming %s and no other check (SMTP-M9-29; smtpproof/testdata/mutations/table.md): %s",
			check, check, check, strings.Join(breaks, "; "))
		excused := []string{}
		for _, cell := range gateM9WitnessExcusedCells() {
			if cell.check == check {
				excused = append(excused, "TLS "+cell.version+" "+cell.mode)
			}
		}
		if 0 < len(excused) {
			text += fmt.Sprintf("; no witness can break %s alone in %s, as the table says why", check, strings.Join(excused, " and "))
		}
		items = append(items, &GateItem{
			Item:  text,
			Tests: []*GateTest{gateSmtpproofTests(".", "", "TestMutatedWitness"+check), shared},
		})
	}
	return items
}

// The flag gate_m9_test.go reads, which only M9's witness-listing command passes.
const gateM9WitnessesFlag = "fault.gate-m9-witnesses"

// smtpproof's evidence table of the mutated witnesses, from this package's directory.
var gateM9WitnessTablePath = []string{"..", "..", "smtpproof", "testdata", "mutations", "table.md"}

// The command the witness-listing item runs in the sidecar repo.
func gateM9WitnessesCommand() []string {
	return []string{"go", "test", "-count=1", "-v", "-run", "^TestGateM9WitnessesAreTheTablesRows$", "./sidecartest/fault", "-" + gateM9WitnessesFlag}
}

// Whether the witnesses M9's exit lists are table's rows, as the listing item reports it: pass when every row of the
// table's first section is a listed witness in one of its cells and every listed witness in every cell is a row, each
// row run by its check's test, and the cells the table's last section excuses are the listed ones; fail naming each
// difference otherwise, and fail for a table with no witness rows.
func gateM9WitnessesListed(table []byte, witnesses []*gateMutatedWitness, excusedCells []*gateWitnessExcusedCell) (string, string) {
	type witnessKey struct {
		check     string
		refusedAt string
		mutation  string
	}
	splitRow := func(line string) []string {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
			return nil
		}
		fields := strings.Split(line[1:len(line)-1], "|")
		for index := range fields {
			fields[index] = strings.TrimSpace(fields[index])
		}
		return fields
	}

	// the table's sections, each a header row, a rule and its rows
	sections := [][][]string{}
	var section [][]string
	for _, line := range strings.Split(string(table), "\n") {
		fields := splitRow(line)
		if fields == nil {
			if section != nil {
				sections = append(sections, section)
				section = nil
			}
			continue
		}
		section = append(section, fields)
	}
	if section != nil {
		sections = append(sections, section)
	}
	witnessHeader := []string{"Check", "TLS", "Mode", "Refused at", "Mutation", "Test"}
	excusedHeader := []string{"Check", "TLS", "Mode", "Why"}
	differences := []string{}
	tableCells := map[witnessKey][]string{}
	tableExcused := []string{}
	witnessRows := 0
	for _, rows := range sections {
		// a header and its rule before any row
		if len(rows) < 2 {
			continue
		}
		switch {
		case slices.Equal(rows[0], witnessHeader):
			for _, fields := range rows[2:] {
				if len(fields) != len(witnessHeader) {
					differences = append(differences, fmt.Sprintf("a witness row of %d columns: %v", len(fields), fields))
					continue
				}
				witnessRows += 1
				check, leg, mode, refusedAt, mutation, test := fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]
				if test != "TestMutatedWitness"+check {
					differences = append(differences, fmt.Sprintf("%s's row %q runs in %s, not TestMutatedWitness%s", check, mutation, test, check))
				}
				key := witnessKey{check: check, refusedAt: refusedAt, mutation: mutation}
				tableCells[key] = append(tableCells[key], leg+" "+mode)
			}
		case slices.Equal(rows[0], excusedHeader):
			for _, fields := range rows[2:] {
				if len(fields) != len(excusedHeader) {
					differences = append(differences, fmt.Sprintf("an excused row of %d columns: %v", len(fields), fields))
					continue
				}
				tableExcused = append(tableExcused, fields[0]+" "+fields[1]+" "+fields[2])
			}
		}
	}
	if witnessRows == 0 {
		return GateOutcomeFail, "the evidence table holds no witness row, so none of what this gate lists is shown"
	}

	listedCells := map[witnessKey][]string{}
	for _, witness := range witnesses {
		key := witnessKey{check: witness.check, refusedAt: witness.refusedAt, mutation: witness.mutation}
		for _, leg := range witness.legs {
			for _, mode := range witness.modes {
				listedCells[key] = append(listedCells[key], leg+" "+mode)
			}
		}
	}
	describe := func(key witnessKey) string {
		return fmt.Sprintf("%s's %q refused at %s", key.check, key.mutation, key.refusedAt)
	}
	for key, cells := range tableCells {
		listed, ok := listedCells[key]
		if !ok {
			differences = append(differences, describe(key)+" is in the table and not listed here")
			continue
		}
		slices.Sort(cells)
		slices.Sort(listed)
		if !slices.Equal(cells, listed) {
			differences = append(differences, fmt.Sprintf("%s runs in %v in the table and %v here", describe(key), cells, listed))
		}
	}
	for key := range listedCells {
		if _, ok := tableCells[key]; !ok {
			differences = append(differences, describe(key)+" is listed here and not in the table")
		}
	}
	listedExcused := []string{}
	for _, cell := range excusedCells {
		listedExcused = append(listedExcused, cell.check+" "+cell.version+" "+cell.mode)
	}
	slices.Sort(tableExcused)
	slices.Sort(listedExcused)
	if !slices.Equal(tableExcused, listedExcused) {
		differences = append(differences, fmt.Sprintf("the table excuses %v and this gate %v", tableExcused, listedExcused))
	}
	if 0 < len(differences) {
		slices.Sort(differences)
		return GateOutcomeFail, "gate_m9.go's witnesses differ from smtpproof's evidence table, so its items list what the suite does not run: " + strings.Join(differences, "; ")
	}
	return GateOutcomePass, fmt.Sprintf("every witness M9's items list is the evidence table's, %d witnesses over %d rows, and the %d excused cells are its", len(listedCells), witnessRows, len(listedExcused))
}

// Every item of M9's exit: see the file header.
func gateM9OutItems(catalog *Catalog) []*GateItem {
	smtpedgeTests := func(names ...string) *GateTest {
		return &GateTest{Repo: "sidecar", Package: "./smtpedgeservice", Names: names}
	}
	items := []*GateItem{
		gateRulesItem(catalog, gateM9OutGate),
		{
			Item: "the rows that pass on their owners' tests alone, with no registered builder: " + strings.Join(gateM9ClauseRows, ", ") +
				" run their owners' fixed cells, each refusal beside its honest control, under none of §22.8's explorer seeds and no FI check after each step, so §22.8's rules above reach none of M9's rows until each has a builder (QD-1084's clause registry)",
		},
		gateInvariantsItem(gateM9OutGate),
		{
			Item: "FS-31's FI-11 and FS-42's M9 step's FI-12 through their oracles (TEST-M4-01's fault.FI(11) over sidecartest.MxProofLedger, TEST-M3-01's fault.FI(12)): no test this sweep found runs either on M9's rows, FS-31's cells asserting on ScriptedMx's and RecordMx's own records and feeding no MxProofLedger (SMTP-M9-30), and the M9 step asserting on its own rows (SMTP-M9-19), so the item above shows the oracles bound, never run here",
		},
	}
	items = append(items, gatePrivacyItems(sidecartest.DefaultPrivacyAsserts(), gateM9OutGate)...)
	if 0 < len(gateStoreClockCases(catalog, gateM9OutGate)) {
		items = append(items, gateStoreClockItem(catalog, gateM9OutGate))
	}

	// §22.10's evidence for smtpproof/SPEC.md's bytes
	items = append(items, gateM9WitnessItems()...)
	items = append(items,
		&GateItem{
			Item:     "the mutated witnesses M9's items list are smtpproof/testdata/mutations/table.md's, check by check, each break with what refused it and its legs and modes, and the cells no witness can break alone are the table's (SMTP-M9-29's evidence table, which TestMutatedWitnessTable holds to the suite's registry)",
			Commands: []*GateCommand{{Repo: "sidecar", Command: gateM9WitnessesCommand()}},
		},
		&GateItem{
			Item: "the checker of the public relation written apart from the prover tree (§22.10's M9 row; SMTP-M9-28): plain Go importing nothing of smtpproof, deriving the public inputs from the ciphertext transcript and the edge's own values, its key schedule against RFC 8448, and agreeing with the gate and the relation on every honest send and on each break by the check it names, through smtpproof's own MX and sidecartest's ScriptedMx and RecordMx",
			Tests: []*GateTest{
				gateSmtpproofTests("./checker", "",
					"TestKeyScheduleReproducesRfc8448", "TestEveryFixedHonestConnectionPasses", "TestTheCheckerRefusesEachBreakByItsCheck",
					"TestTheCheckerReadsTheHeaderBlockAsSpecDoes", "TestTheCheckerReadsDataAndRepliesAsSpecDoes", "TestTheCheckerImportsNothingFromTheProverTree",
					"TestTheCheckerHoldsTheIssuedValuesToTheirSpelling", "TestTheCheckerReadsTheScanStateByItsDefinition", "TestTheCheckerRefusesEachHeaderRuleAtItsRecord",
					"TestTheCheckerRefusesKeysOfOtherWidths",
				),
				gateSmtpproofTests(".", "",
					"TestCheckerAgreesThatEveryHonestSendPasses", "TestCheckerAgreesOverSeveralEnvelopeGroups", "TestCheckerAndTheGateNameTheSameChecks",
					"TestCheckerAgreesOnHonestSendsThroughSidecartestsMxs", "TestCheckerAgreesThroughALateTicketAndSplitReplies",
					"TestCheckerAndTheGateNameTheSameChecksThroughARecordMx", "TestCheckerAndTheGateNameTheSameChecksOnTheDetailsCellsThroughARecordMx",
					"TestCheckerAgreesOnTheHeaderCarryAtEveryCut", "TestCheckerAgreesOnTheBodyCarryAtEveryCut", "TestCheckerAgreesOnASingleFieldEndingTheFirstRecord",
					"TestHeaderCircuitTheGateAndTheCheckerRefuseAlike",
				),
			},
			External: "people: §22.10 asks for the checker apart from the prover tree, and SMTP-M9-28 for an author who wrote neither the circuits nor relation.go; this checker and the circuits are both the build's drafts, so an engineer outside both reads it, or writes their own, before the bytes freeze",
		},
		&GateItem{
			Item:  "FS-31's scripted MXs as §22.10's M9 evidence: no CHUNKING, CHUNKING only before TLS, no PIPELINING, MAIL or RCPT refused, mixed recipients, no 354 and a late NewSessionTicket, each mismatch failing before any effect in every leg and mode, as FS-31's row above runs them and smtpproof/testdata/fs31/matrix.md lists them",
			Tests: []*GateTest{gateFs31PlainTests, gateFs31EngineTests, gateFs31T3Tests},
		},
		&GateItem{
			Item: "the bytes M9's exit freezes reproduce (§23.8's M9 freeze; SMTP-M9-33): each part's statement as field elements, its counts and carries, the edge's templates and a key-part proof under a test setup's verifying key, from fixed connections that prove under every production shape and set every flag a shape reads",
			Tests: []*GateTest{
				gateSmtpproofTests(".", "", "TestSpecVectorsReproduce", "TestSpecVectorsCoverEveryShape", "TestSpecPi1ProofVectorVerifies"),
			},
		},
		&GateItem{
			Item:     "two engineers who did not write the circuits argue SPEC.md's soundness in writing, its steps S1 to S7 and K1 to K4 (§22.10's M9 row; D-SMTP-16)",
			External: "people: two non-authors' written argument; no external audit stands in for it or is asked for (owner decisions 99, 119)",
		},
		&GateItem{
			Item: "§22.9's ZK row and D-SMTP-16's speed: p95 per part and per send, BDAT for a 4 KiB header block and 10 recipients and DATA for a 100 KiB message, through smtpproof/bench, whose harness runs one small case here and refuses what it cannot run (SMTP-M9-32)",
			Tests: []*GateTest{
				gateSmtpproofTests("./bench", "", "TestBenchRunsASmallCaseAndPrintsAUnitsRow", "TestBenchRefusesWhatItCannotRun", "TestBenchPercentilesAreNearestRank"),
			},
			External: "hardware: D-SMTP-16's runs on an Apple M1 MacBook Air (8 GB) and an AWS m5.large, under a key set smtpproof/setup wrote, at production sizes; this host's run is a smoke, which is no evidence",
		},
		&GateItem{
			Item:     "D-SMTP-16's coverage: Gmail, Outlook.com, Exchange Online, Yahoo, AOL, iCloud and at least 95% of the census's MX domains offer a TLS version and suite the circuits cover (§14.5; the M7 census, D-MAIL-9)",
			External: "production: the census's probe of the Tranco top 10,000's MXs from the production edges",
		},
		&GateItem{
			Item:     "D-SMTP-16's interop and §22.9's MTA row: through the sidecar's own client, strict DMARC passes at Gmail, Outlook.com, Microsoft 365, Yahoo, iCloud, SES, Proton and Fastmail in both modes, DATA forced where CHUNKING is offered and TLS 1.2 to Exchange Online included, with §14.4's levels, DKIM, FCrDNS, and JMRP and CFL joins",
			External: "production: real accounts at each provider and sends from the shared lb addresses",
		},
		&GateItem{
			Item:     "D-SMTP-16's gate whole, or burner email launches receive-only (owner decisions 9, 35; BS1): the soundness, speed, coverage and interop rows above pass on their own evidence, and a miss is reported for the owner, never hidden by a smoke run on this host",
			External: "people: the owner hears where the proofs stand against D-SMTP-16, and BS1 stays receive-only until every row passes",
		},
	)

	// §22.7's scenarios, and S6 as its owners run it
	items = append(items, gateScenarioItems(sidecartest.DefaultScenarioRegistry(), gateM9OutGate)...)
	items = append(items,
		&GateItem{
			Item: "S6, send mail, as its owners' tests run it on SmtpSendWorld and M9World, outside RunScenario (§22.7; §3.7's F5; SMTP-M9-31, MAIL-M9-06): no record forwarded before its proof verifies, no unauthenticated MX, a message over the DATA cap too_large for the non-CHUNKING domain alone, and §15.10's forwarding code, forwards and relays through MAIL's code, on T2; the first three on T3",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{
					"TestS6NoRecordReachesTheMxBeforeItsPart", "TestS6NoUnauthenticatedMx", "TestS6TooLargeForTheNonChunkingDomainAlone",
				}},
				{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_testhooks", Names: []string{
					"TestS6ForwardingAddressIsConfirmedByACodeThroughSmtp", "TestS6ForwardAndRelayThroughMailsCode",
				}},
				gateS6T3Tests,
			},
		},
		&GateItem{
			Item: "S6's §15.10 forwarding rows on T3 (§22.7's S6 tiers; MAIL-M9-06): no test this sweep found runs the forwarding code, forwards and relays on server's stores, which MAIL-M9-06 ran on T2 alone",
		},
		&GateItem{
			Item: "S10's records (§22.7; §14.6; DNS-M9-01): a replying burner's first selector writing <blabel>'s copies of the wildcard's MX, A and AAAA in its journal write and its last deleting them, a receive-only burner creating no child, a copy answering the wildcard's current records, and S10 registered whole on T2 and T3",
			Tests: []*GateTest{
				gatePendingTests("./model", "TestDnsBurnerSelectorsKeepTheLabelsMail", "TestDnsDkimSelectorWrites"),
				{Repo: "sidecar", Package: "./dnsservice", Names: []string{"TestPlanCopyRowsBurnerSelectors", "TestBurnerSelectorCopyAnswersTheWildcardsCurrentRecords"}},
				{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_testhooks", Names: []string{"TestS10IsRegisteredWholeOnT2AndT3"}},
			},
		},
	)

	// §23.4's exit criteria beside FS-123's send checks and outcomes
	items = append(items,
		&GateItem{
			Item: "DANE-only MXs reached and unauthenticated ones refused (§23.4's M9 exit; TL1, owner decision 38; SMTP-M9-05, SMTP-M9-06): DANE-EE and DANE-TA matched, PKIX usages ignored, a mismatch and an unproven TLSA no authentication, a self-signed MX no PKIX root vouches for reached through TL1 alone, by the dialog and by a send through the edge, a mismatch never overridden and a stripped TLSA under a TL1 pin sending no DATA; S6's unauthenticated MX getting no byte inside TLS on T2 and T3",
			Tests: []*GateTest{
				gateSidecarTests(
					"TestSmtpDaneEeMatchesTheLeafWhateverItsNameAndExpiry", "TestSmtpDaneTaAnchorsTheLeafsChain", "TestSmtpDanePkixUsagesAreIgnored",
					"TestSmtpDaneMismatchRefusesTheMx", "TestSmtpDaneWithoutAProvenTlsaIsNoAuthentication", "TestSmtpDaneOnlyMxIsReached", "TestSmtpTlsReachesTl1ByDane",
					"TestSmtpTlsDaneMismatchIsNotOverridden", "TestSmtpTlsStrippedTlsaUnderATl1PinSendsNoData",
				),
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{"TestS6NoUnauthenticatedMx"}},
				gateS6T3Tests,
			},
			External: "production: DANE-only MXs among real recipients, which no local run reaches",
		},
		&GateItem{
			Item: "halt, ARF and RUA joins (§23.4's M9 exit; §14.8; SMTP-M9-15, SMTP-M9-16, SMTP-M9-17, ABUSE-M9-01): high, medium and low joins against the send log, replays and forgeries dropped and no Received address kept; an allowlisted loop's ARF a complaint once its join lands; a halt reaching the edge within one reload and the sender holding its message deferred; an aggregate counted once a reporter and report id; RUA counts past proven sends by over 20% and 5 opening a case with no halt; and §21 taking each halt to a case and an action, each complaint to review and the RUA case to no action",
			Tests: []*GateTest{
				smtpedgeTests(
					"TestAttributionHighJoin", "TestAttributionMediumJoin", "TestAttributionLowJoinNeverHalts", "TestAttributionXUrRefReplayUnderAnotherNetworksDkimIsDropped",
					"TestAttributionReplayFromAnotherAddressOrTimeIsDropped", "TestAttributionForgeriesAreDropped", "TestAttributionStoresNoReceivedAddress",
					"TestReportIntakeArfIsUnattributedUntilAJoinLands", "TestReportIntakeArfFromAnAllowlistedLoopIsAComplaint",
					"TestReportIntakeCountsAGzipXmlAggregateOncePerReporterAndReportId", "TestHaltCommunityFirstComplaintHaltsTheNetwork",
					"TestHaltFraudHaltsAnyTierWithReview", "TestHaltReachesTheEdgeAndALiftAdmitsAgain", "TestHaltThreeHaltsInThirtyDaysReachTheSinkOnce",
					"TestSmtpSenderHaltReachesTheNextSendWithinAReload", "TestSmtpReconcileOpensACaseAboveTwentyPercentAndFive",
					"TestSmtpReconcileOneConnectionTenRecipientsRaisesNothing",
				),
				gatePendingTests("./controller",
					"TestSmtpReconcileOpensACaseOverTwentyOnePercentAndFive", "TestAbuseMailHaltBecomesACaseAndAnAction", "TestAbuseMailComplaintsReachReview",
					"TestAbuseMailRuaOpensACaseWithNoHalt", "TestAbuseMailOnSmtpsLadder",
				),
			},
		},
		&GateItem{
			Item: "§14's privacy rows (§22.7; R-SMTP-7, R-SMTP-10, I-2, I-13; SMTP-M9-31): canaries in a mail body, its subject, its From display name and a recipient's local part found in nothing the edge read, answered or kept, and no DKIM key anywhere, on T2 and T3; a feedback loop's report and an abuse@ mail's canaries only in mx-4's listener input and in copies sealed to the network's mail key, on T2",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_testhooks", Names: []string{
					"TestSmtpSendCarriesNoCanaryPastTheDevice", "TestSmtpReportCanariesStayInTheListenerInput", "TestSmtpAttributedReportCanariesStaySealed",
				}},
				{Repo: "server", Package: "./smtpedgehost", Tags: gateM9SmtpEdgeTags, Stores: true, Names: []string{"TestT3SmtpSendCarriesNoCanaryPastTheDevice"}},
			},
		},
		&GateItem{
			Item: "§14's report canary rows on T3 (SMTP-M9-31): no test this sweep found scans a report's canaries on server's stores, since mxedge's platform intake attributes and seals nothing there yet",
		},
		&GateItem{
			Item: "the schema guard at M9 (I-18; SMTP-M9-31): every smtp field maps to its row, smtp-1 to smtp-6 among them with smtp-3, smtp-5 and smtp-6 on server's tables, and {smq_} is a Redis family of its own",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{"TestSchemaGuard", "TestMetadataListKeepsRedisSuffixesApart"}},
				{Repo: "sidecar", Package: "./check", Tags: "sidecar_check", Names: []string{"TestSchemaGuard"}},
			},
		},
		&GateItem{
			Item: "the preamble on its inline path and the CROSSSLOT lint (§22.5's hot-path gates, §22.4; I-12; SMTP-M9-10, SMTP-M9-11): a preamble asking no store and one {smq_} script, the quota's scripts each in one slot",
			Tests: []*GateTest{
				smtpedgeTests("TestPreamblePathAsksNoStoreAndOneScript", "TestQuotaOneScriptPerPreamble", "TestQuotaScriptsPassTheCrossslotLint"),
			},
		},
		&GateItem{
			Item: "the preamble gate on server's host through InlinePath, held to budgets.yml's smtp-preamble-gate row with PostgreSQL refused and its Redis calls counted (§22.5; SMTP-M9-10): its InlinePath has not landed, so the row reads missing",
		},
		&GateItem{
			Item: "smtpedge's load harness (§22.8's smtpedge row; SMTP-M9-32): Team quota held across many networks and halts within a minute with no overrun, and each network's day taken and no more, at a small size on a fake clock",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{"TestLoadSmtpEdgeHoldsTeamQuotaAndHaltsWithinAMinute", "TestLoadSmtpEdgeTakesEachNetworksDayAndNoMore"}},
			},
			External: "hardware: the evidence run on T5's performance host, a deployed smtpedge through ur/smtpedge streams at the 1,000-network default on a real Redis; this host's run is a smoke",
		},
		&GateItem{
			Item:     "HE's TCP 25 egress, reverse delegation and feedback loops, before any send from the shared lb addresses (§23.7's M9 entry; owner decision 124; §14.9), with the breakers' Postmaster Tools and SNDS accounts (owner decision 611)",
			External: "people and production: Hurricane Electric's answer on TCP 25, the PTRs and the loops, and the owner's accounts placed in vault",
		},
	)
	if later := gateLaterCases(catalog, gateM9OutGate); 0 < len(later) {
		items = append(items, &GateItem{
			Item:     "not yet due at M9, and shown here as no row and no pass: " + strings.Join(later, ", ") + " (§23.6's gate map)",
			External: "a later gate: each case passes at the gate catalog.yml holds it at",
		})
	}
	return items
}

var gateM9Sweep = RegisterGateSweep(&GateSweep{
	Gate:  "M9",
	Cases: gateM9Cases(DefaultCatalog()),
	Items: gateM9OutItems(DefaultCatalog()),
})

// M9's entry review reads its design closure, which a person signs, smtpproof/SPEC.md's specification, which freezes
// there, and the lead time due by then.
var gateM9InSweep = RegisterGateSweep(&GateSweep{
	Gate: "M9-in",
	Items: []*GateItem{
		{
			Item:     "§23.6's M9 design closure: the SMTP server-state relation (§14); 22.10's M9 evidence; the send-capability and result model (§14, §15, §18)",
			External: "people: the Gn-in review reads and signs the closure (§23.8)",
		},
		{
			Item: "smtpproof/SPEC.md's specification freeze (§22.10's M9 row, Gn-in; D-SMTP-16, D-SMTP-22; SMTP-M9-33): the relation, its public inputs and E1-E3 and Z1-Z9 (§14.5), each check with its section, its tests and a mutated witness, the argument's steps S1 to S7 and K1 to K4 with theirs, and the header scan's literals each shorter than a header record",
			Tests: []*GateTest{
				gateSmtpproofTests(".", "", "TestSpecNamesEveryCheck", "TestSpecHeaderRecordsOutlastEveryLiteral"),
			},
			External: "people: the entry review reads SMTP-M9-33's draft 3, the freeze candidate, and freezes it (§23.8; D-PHASE-7)",
		},
		{
			Item:     "HE's TCP 25 egress, reverse delegation and feedback loops, due at M9's entry (§23.7; owner decision 124)",
			External: "people and production: asked at M0, unknown until Hurricane Electric answers",
		},
	},
})
