// I-18's walk over the service files, as a test: every message either stays sealed or shows a server its fields, and
// every field shown maps to a §2.8 row or is listed as raised. The walk was once done by hand, took a file's header at
// its word and so skipped what gates parse in record.proto, so a header's claim is checked here too, and each row's
// words are read from metadata_list.yml rather than remembered.
//
// This stands in for the proto half of §22.7's schema guard (TEST-M1-02), which has not landed. When it does, these
// accounts belong in its field map. It stops at the service files, and testUnwalkedFiles names the rest, so a new file
// has to say which it is.

package protocol

import (
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// §2.8's list as the repository carries it: make metadata copies it byte for byte, and check/ holds the two alike.
const testMetadataListPath = "../metadata_list.yml"

// The sentence a file's header uses to say it shows a server nothing.
const testSealedClaim = "no server reads a field"

// A §2.8 row's id, on a line of its own.
var testRowId = regexp.MustCompile(`^[a-z]+-[0-9]+:$`)

// What this walk reads, in the order §6.11 numbers their services.
var testWalkedFiles = []string{
	"protocol/socket.proto",
	"protocol/gkm.proto",
	"protocol/evs.proto",
	"protocol/evsindex.proto",
	"protocol/search.proto",
	"protocol/tls.proto",
	"protocol/smtp.proto",
	"protocol/mail.proto",
	"protocol/record.proto",
	"protocol/directory.proto",
}

// Files this walk leaves to others: protos-bridge-row-fields and TestSealedStatementsShowOnlyIds answer for acl, config
// and bridge's rows, and nothing yet walks the envelope, stream and push wires against connect-2 and connect-4.
var testUnwalkedFiles = []string{
	"protocol/acl.proto",
	"protocol/config.proto",
	"protocol/envelope.proto",
	"protocol/push.proto",
	"protocol/stream.proto",
	"protocol/types.proto",
	"protocol/bridge/auth.proto",
	"protocol/bridge/bridge.proto",
	"protocol/bridge/signed.proto",
}

// Messages no server reads a field of. evsindex.proto's and directory.proto's are files evs seals as it seals any
// file, search.proto's ride a Required session peer to peer (connect-5), MailAuthEvidence and its results sit in a
// deposit's sealed header, a record entry and what its sealed body holds are files in a writer's stream, and EvsImport
// rides a push's sealed metadata. What their sizes and timing show has its own rows, evs-26, evs-27 and connect-5.
var testSealedMessages = []string{
	"IndexSettings", "IndexLock", "IndexErasureSet", "IndexErasure", "IndexErased", "IndexFileHeader", "IndexCoverage",
	"IndexManifest", "IndexShard", "IndexWatermark",
	"SearchRequest", "SearchRepo", "SearchFilters", "SearchField", "SearchReply", "SearchCoverage", "SearchHit",
	"SearchCounts",
	"MailAuthEvidence", "AuthLimits", "SpfResult", "DkimResult", "DmarcResult", "ArcSet", "ArcResult",
	"RecordHeader", "ContentRef", "RecordEntry", "ApprovalRequest", "ReachReceipt", "Coverage", "RetentionPolicy",
	"DirectoryCard", "RepoAnnouncement", "Announcement", "AnnounceWho", "AnnounceWhat", "AnnounceWhere", "Service",
	"Claim", "Handoff", "DirectoryRequest", "RequestTarget", "DirectoryDecision", "DirectoryNotice", "DecisionRef",
	"DirectoryErasureRequest",
	"EvsImport",
}

// A row's words for some of a message's fields, or, with no fields, for the message as a whole.
type testRowView struct {
	row    string
	quote  string
	fields []string
}

// What servers see of a message. Each field is in one place: a view that names it, raised, or sealed. A view with no
// fields takes every field left over. raised holds what a server reads and no row names, each asked in
// protos-services-metadata-rows or protos-services-canonical-action, and an answer moves it to a view.
type testServerView struct {
	views  []testRowView
	raised []string
	sealed []string
}

// The common account: one row speaks of the message as a whole.
func testWholeView(row string, quote string) testServerView {
	return testServerView{views: []testRowView{{row: row, quote: quote}}}
}

// §2.8's account of each message a server parses or writes.
var testMessageViews = map[string]testServerView{
	"SocketHint":         testWholeView("connect-4", "topic versions and hints for core, team, sock"),
	"SocketTicket":       testWholeView("sock-2", "issued tickets"),
	"SignedSocketTicket": testWholeView("sock-2", "issued tickets"),

	"GkmCommitHeader": testWholeView("gkm-2", "group_id, epoch, content type, generation, auth pin"),
	"UrMlsCredential": {
		views: []testRowView{
			{
				row:   "gkm-4",
				quote: "credential: sidecar_id, identity key, suite, not_after, admission hash, signature",
				fields: []string{
					"sidecar_id", "identity_public_key", "cipher_suite", "not_after", "admission_sha256", "identity_signature",
				},
			},
			{row: "gkm-4", quote: "signature key", fields: []string{"mls_signature_public_key"}},
		},
		// api-5 already shows it, as "identity public key and algorithm".
		raised: []string{"identity_alg"},
	},
	"GenRotate": {
		views: []testRowView{{
			row: "gkm-7",
			quote: "GenRotates (group, generation, parent and own commitments, cause, auth pin, time, holders hash, signer; " +
				"GenLink and leaf-wrap ciphertexts; the drop public key",
			fields: []string{
				"group_id", "generation", "parent_commitment", "commitment", "cause", "auth", "time_ms", "holders_sha256",
				"genlink", "leaf_wrap", "drop_public_key",
			},
		}},
		// gkm-1 already shows repo_id beside group_id; the other two are new values.
		raised: []string{"repo_id", "wrap_count", "drop_not_after_ms"},
	},
	"LeafWrap": {
		views: []testRowView{{row: "gkm-7", quote: "leaf-wrap ciphertexts", fields: []string{"ciphertext"}}},
		// gkm-2 already shows an epoch.
		raised: []string{"epoch"},
	},
	"KeyDelivery":    testWholeView("gkm-7", "staged and late wraps (group, generation, commitment"),
	"ReaderWrap":     testWholeView("gkm-7", "staged and late wraps"),
	"DelegationWrap": testWholeView("gkm-7", "staged and late wraps"),
	"ReaderKey":      testWholeView("gkm-4", "ReaderKeys (owner decision 114)"),
	"GroupForm":      testWholeView("gkm-1", "GroupForm chain (repo_id, group_id, previous group, generation, signer)"),
	"GkmHint":        testWholeView("connect-4", "topic versions and hints for core, team, sock, tls, mail, dns, gkm"),

	"EvsPush":         testWholeView("evs-12", "Signed EvsPush cleartext"),
	"EvsTokenPath":    testWholeView("evs-12", "covering token prefixes"),
	"EvsChange":       testWholeView("evs-12", "changes of token path, base entry version and entry hash"),
	"EvsPushPart":     testWholeView("evs-12", "its EvsPushPart"),
	"EvsEntryVersion": testWholeView("evs-12", "cleartext entry versions"),
	"EvsNameTable":    testWholeView("evs-11", "per directory a name table of child tokens"),
	"EvsName":         testWholeView("evs-11", "individually sealed names"),
	"EvsLocator":      testWholeView("evs-11", "chain locators"),
	"EvsPathMap":      testWholeView("evs-15", "Signed EvsPathMap parts"),
	"EvsPathMove":     testWholeView("evs-15", "moves of old token path to new token path"),
	"EvsSourcePath":   testWholeView("evs-15", "every live path's token in each source epoch"),
	"EvsReseed":       testWholeView("evs-12", "EvsReseed statements (repo, ref, re-seeded version and chain, incident id"),
	"EvsDropHistory": testWholeView(
		"evs-12", "DROP payload bodies (drop id, action, a cancel's drop id and version, not_before_ms, preview id",
	),
	"EvsDropPath": testWholeView(
		"evs-12",
		"per path lineage its token path in each epoch with their map parts, through_version, boundary, count and list hash",
	),
	"EvsUploadReceipt": {
		views: []testRowView{{
			row: "evs-4",
			quote: "upload receipts (repo, segment id, padded size, upload time, uploader sidecar, " +
				"whether its header is a kind-5 header), MAC'd by evs",
			fields: []string{
				"repo_id", "segment_id", "padded_size", "upload_ms", "uploader_sidecar_id", "versionless", "mac",
			},
		}},
		raised: []string{"key_id"},
	},
	"EvsPlace":       testWholeView("evs-3", "the batch place of its statement and payload"),
	"EvsHead":        testWholeView("evs-3", "the commit point; version v, chain C_v"),
	"EvsOverlay":     testWholeView("evs-3", "overlay base"),
	"EvsSealLease":   testWholeView("evs-3", "any seal lease"),
	"EvsPathEpoch":   testWholeView("evs-3", "path epoch with its listed sources, any due epoch and a mapper's creation block"),
	"EvsEpochSource": testWholeView("evs-3", "path epoch with its listed sources"),
	"EvsCollect":     testWholeView("evs-3", "the marker collection (EvsCollect"),
	"EvsHeadChanged": testWholeView("connect-4", "and evs:<repo_id>, each hint at most 256 B"),

	"TlsEdgeOpen": {views: []testRowView{
		{row: "tls-2", quote: "visitor IP and port", fields: []string{"client_ip", "client_port"}},
		{row: "tls-1", quote: "the SNI", fields: []string{"server_name"}},
		{
			row:    "tls-1",
			quote:  "the whole ClientHello (ALPN list, ECH presence, size)",
			fields: []string{"alpn", "client_hello_byte_count"},
		},
		{row: "tls-3", quote: "connection_id", fields: []string{"connection_id"}},
		{row: "sock-2", quote: "issued tickets", fields: []string{"expire_time_millis"}},
	}},

	"SmtpPreamble": {
		views: []testRowView{{
			row: "smtp-1",
			quote: "recipient domain, recipient count, Message-ID, header-From domain (a network, burner or verified Team domain), " +
				"DKIM selector with d=, message byte count, retry-of send id, flags (BULK, REQUIRETLS, BURNER)",
			fields: []string{
				"recipient_domain", "recipient_count", "message_id", "header_from_domain", "dkim_selector",
				"message_byte_count", "retry_of_send_id", "flags",
			},
		}},
		raised: []string{"version"},
	},
	"SmtpPreambleResult": {
		views: []testRowView{
			{
				row:    "smtp-2",
				quote:  "the issued send_id, X-UR-Ref and Feedback-ID",
				fields: []string{"send_id", "x_ur_ref", "feedback_id"},
			},
			{row: "smtp-2", quote: "its helo_name", fields: []string{"helo_name"}},
			{row: "smtp-2", quote: "MX host and IP", fields: []string{"mx_host"}},
			{row: "smtp-2", quote: "the DNSSEC chain", fields: []string{"dnssec_chain"}},
			{row: "smtp-2", quote: "banner and pre-TLS EHLO and STARTTLS replies", fields: []string{"ehlo_keywords"}},
			{row: "smtp-2", quote: "bytes, result", fields: []string{"code"}},
		},
		raised: []string{"retry_after_ms"},
	},
	"SmtpProof":       testWholeView("smtp-2", "proofs π1 to π3 and, in DATA mode, one per later body part"),
	"SmtpProofResult": testWholeView("smtp-2", "bytes, result"),

	"MailIngress": {
		views: []testRowView{
			{
				row:    "mx-1",
				quote:  "MailIngress, which carries sender IP, EHLO, PTR and listings to the receiver sealed",
				fields: []string{"sender_ip", "ehlo_name", "ptr_name", "ip_listings"},
			},
			{row: "mx-1", quote: "sender IP and port (PROXY v1)", fields: []string{"sender_port"}},
			{row: "mx-1", quote: "SNI (the network's mail host", fields: []string{"sni"}},
			{row: "mx-1", quote: "timing, size, result", fields: []string{"receive_time_millis"}},
		},
		raised: []string{"version"},
	},

	// Every gate parses these (§16.6), and a GrantActivate carries them into the log (§8.8).
	"ApprovalDecision": {
		views: []testRowView{
			{
				row:   "api-10",
				quote: "approval id, request hash, payload hash, decision, uses, expiry, approver member, evidence channel",
				fields: []string{
					"approval_id", "request_sha256", "payload_sha256", "decision", "uses", "not_after_millis",
					"approver_member_id", "channel",
				},
			},
			{row: "api-10", quote: "SSHSIG, evidence hash", fields: []string{"sshsig", "evidence_sha256"}},
			{row: "api-10", quote: "the requester sidecar id", fields: []string{"requester_sidecar_id"}},
			{row: "api-10", quote: "the approver's projection pin", fields: []string{"auth_pin"}},
		},
		raised: []string{"version"},
	},
	"ApprovalCancel": testWholeView("api-10", "ApprovalCancels (approval id, signer)"),
	// A gate hashes the stored bytes and parses them, so a set field shows. Which field may be set on which path is
	// protos-services-canonical-action's question. Nothing builds or parses one yet.
	"CanonicalAction": {
		views: []testRowView{
			{
				row:    "api-10",
				quote:  "the canonical action's fields that gate already sees (host, port, audience, expiry)",
				fields: []string{"host", "port", "audience", "expires_millis"},
			},
			{
				row:    "api-7",
				quote:  "grant activations and revocations",
				fields: []string{"rule_id", "subject", "grant_dst", "grant_allow"},
			},
			{
				row: "api-7",
				quote: "publish rules' application modes (http or raw) and raw link grants' client-certificate SPKI SHA-256, " +
					"which a requested grant's GrantActivate also shows",
				fields: []string{"app_mode", "link_spki_sha256"},
			},
			{
				row:    "api-7",
				quote:  "rules with targets, actions, ports, the CIDRs of ip targets",
				fields: []string{"target_sidecar_id", "target_port", "cidrs"},
			},
			{row: "api-7", quote: "public names", fields: []string{"socket_name"}},
		},
		// dns-1 already holds the dns_* values, and sock-1 weight and ALPN, each as its own service's state.
		raised: []string{
			"kind", "version", "scope", "dns_name", "dns_type", "dns_value", "dns_ttl", "local_port", "weight", "alpn",
		},
		// api-10: "recipients and previews stay sealed". The rest serve actions a daemon spends itself: mail, evs writes,
		// aliases and restores, none of which reaches a gate or a GrantActivate.
		sealed: []string{
			"recipients", "body_sha256", "preview", "repo_id", "path", "content_sha256", "base_version", "alias",
			"restore_run_id", "restore_paths", "restore_preview_id", "alias_group", "versioning",
		},
	},
}

// §2.8's rows as written, by id. sidecartest's strict reader parses these same bytes, and this package only asks whether
// a row still says something, so it reads them as text.
func testReadRows(t *testing.T) map[string]string {
	list, err := os.ReadFile(testMetadataListPath)
	if err != nil {
		t.Fatal(err)
	}
	rowTexts := map[string]string{}
	row := ""
	for line := range strings.SplitSeq(string(list), "\n") {
		if testRowId.MatchString(line) {
			row = strings.TrimSuffix(line, ":")
			continue
		}
		if row != "" {
			rowTexts[row] += line + "\n"
		}
	}
	// §2.8 holds 94 rows, withdrawn ones included, and the floor says why every view fails if a parser finds few.
	if len(rowTexts) < 90 {
		t.Fatalf("found %d rows", len(rowTexts))
	}
	return rowTexts
}

// How the service files differ from their accounts: a message neither sealed nor walked, a field in no place or two,
// and a row that is gone, withdrawn or no longer says what its view quotes.
func testWalkDifferences(files *protoregistry.Files, rowTexts map[string]string) []string {
	differences := []string{}
	report := func(format string, arguments ...any) {
		differences = append(differences, fmt.Sprintf(format, arguments...))
	}
	files.RangeFilesByPackage(testProtoPackage, func(file protoreflect.FileDescriptor) bool {
		if !slices.Contains(testWalkedFiles, file.Path()) && !slices.Contains(testUnwalkedFiles, file.Path()) {
			report("%s is neither walked nor left to another account", file.Path())
		}
		return true
	})
	walked := map[string]bool{}
	for _, path := range testWalkedFiles {
		file, err := files.FindFileByPath(path)
		if err != nil {
			report("%s: %v", path, err)
			continue
		}
		messages := file.Messages()
		for i := range messages.Len() {
			message := messages.Get(i)
			name := string(message.Name())
			walked[name] = true
			view, shown := testMessageViews[name]
			sealed := slices.Contains(testSealedMessages, name)
			if shown == sealed {
				report("%s: %s is sealed %t and has a view %t: a server reads it or it does not", path, name, sealed, shown)
				continue
			}
			if sealed {
				continue
			}
			fieldCounts := map[string]int{}
			everyField := false
			for _, rowView := range view.views {
				rowText, ok := rowTexts[rowView.row]
				switch {
				case !ok:
					report("%s cites row %s, which §2.8 does not hold", name, rowView.row)
				case strings.Contains(rowText, "withdrawn:"):
					report("%s cites row %s, which is withdrawn", name, rowView.row)
				case !strings.Contains(rowText, rowView.quote):
					report("%s: row %s no longer says %q", name, rowView.row, rowView.quote)
				}
				if len(rowView.fields) == 0 {
					everyField = true
				}
				for _, field := range rowView.fields {
					fieldCounts[field]++
				}
			}
			for _, field := range slices.Concat(view.raised, view.sealed) {
				fieldCounts[field]++
			}
			fields := message.Fields()
			for j := range fields.Len() {
				field := string(fields.Get(j).Name())
				if fieldCounts[field] > 1 {
					report("%s.%s is in %d places", name, field, fieldCounts[field])
				}
				if fieldCounts[field] == 0 && !everyField {
					report("%s.%s reaches a server and no row names it: add its row (I-18), or raise it", name, field)
				}
				delete(fieldCounts, field)
			}
			for field := range fieldCounts {
				report("%s lists %s, which it does not declare", name, field)
			}
		}
	}
	for name := range testMessageViews {
		if !walked[name] {
			report("%s has a view and no walked file declares it", name)
		}
	}
	for _, name := range testSealedMessages {
		if !walked[name] {
			report("%s is listed as sealed and no walked file declares it", name)
		}
	}
	return differences
}

// Whether a header, everything above a file's syntax statement, says no server reads the file. The sentence may wrap.
func testClaimsSealed(header string) bool {
	return strings.Contains(strings.Join(strings.Fields(strings.ReplaceAll(header, "//", " ")), " "), testSealedClaim)
}

// What a file's header claims against what its messages show: a file saying no server reads a field of it may hold
// no message with a view.
func testSealedClaimDifferences(files *protoregistry.Files, path string, header string) []string {
	if !testClaimsSealed(header) {
		return nil
	}
	file, err := files.FindFileByPath(path)
	if err != nil {
		return []string{err.Error()}
	}
	differences := []string{}
	messages := file.Messages()
	for i := range messages.Len() {
		if _, shown := testMessageViews[string(messages.Get(i).Name())]; shown {
			differences = append(differences, fmt.Sprintf(
				"%s says %s, and a server reads %s", path, testSealedClaim, messages.Get(i).Name(),
			))
		}
	}
	return differences
}

// I-18: every message of the service files has an account, and every field a server reads names its row or is raised.
func TestEveryServiceFieldHasItsRow(t *testing.T) {
	for _, difference := range testWalkDifferences(protoregistry.GlobalFiles, testReadRows(t)) {
		t.Error(difference)
	}
}

// A header's word cannot stand in for the walk: a file that says it shows a server nothing holds nothing a server reads.
func TestSealedHeadersHoldNoServerView(t *testing.T) {
	claims := 0
	for _, path := range testWalkedFiles {
		source, err := os.ReadFile(strings.TrimPrefix(path, "protocol/"))
		if err != nil {
			t.Fatal(err)
		}
		header, _, found := strings.Cut(string(source), "\nsyntax = ")
		if !found {
			t.Fatalf("%s has no syntax statement", path)
		}
		if testClaimsSealed(header) {
			claims++
		}
		for _, difference := range testSealedClaimDifferences(protoregistry.GlobalFiles, path, header) {
			t.Error(difference)
		}
	}
	// directory.proto, evsindex.proto and search.proto make the claim, and a walk that found none proves nothing.
	if claims != 3 {
		t.Errorf("%d files make the claim", claims)
	}
}

// The header record.proto carried, which sent I-18's walk past three messages gates parse, and each way the walk's
// own account can go wrong.
func TestWalkCatchesPlantedFaults(t *testing.T) {
	const (
		gkm    = "protocol/gkm.proto"
		record = "protocol/record.proto"
	)
	oldHeader := "// The record's primitives (§16.8), sealed end to end, so no server reads a field here. RECORD.md's\n" +
		"// kinds, class numbers and entry bodies are not here. A bare section number, as in 16.6, is DESIGN.md's.\n"
	differences := testSealedClaimDifferences(protoregistry.GlobalFiles, record, oldHeader)
	for _, name := range []string{"ApprovalDecision", "ApprovalCancel", "CanonicalAction"} {
		if !testHasDifference(differences, "a server reads "+name) {
			t.Errorf("record.proto's old header passed for %s: %v", name, differences)
		}
	}

	addField := func(path string, message string, name string, number int32) func(fileProtos testFileProtos) {
		return func(fileProtos testFileProtos) {
			planted := testPlantedMessage(t, fileProtos, path, message)
			planted.Field = append(planted.Field, testNewField(name, number, descriptorpb.FieldDescriptorProto_TYPE_BYTES))
		}
	}
	addMessage := func(path string) func(fileProtos testFileProtos) {
		return func(fileProtos testFileProtos) {
			file := fileProtos[path]
			file.MessageType = append(file.MessageType, &descriptorpb.DescriptorProto{Name: proto.String("Stray")})
		}
	}
	cases := []struct {
		name   string
		want   string
		mutate func(fileProtos testFileProtos)
	}{
		{
			name:   "a field a gate would read, with no row",
			want:   "ApprovalDecision.plaintext reaches a server",
			mutate: addField(record, "ApprovalDecision", "plaintext", 14),
		},
		{
			name:   "a field of the action a gate hashes, with no row",
			want:   "CanonicalAction.stray reaches a server",
			mutate: addField(record, "CanonicalAction", "stray", 38),
		},
		{
			name:   "a field of a stored credential, with no row",
			want:   "UrMlsCredential.stray reaches a server",
			mutate: addField(gkm, "UrMlsCredential", "stray", 9),
		},
		{
			name:   "a message nobody has walked, in the file the walk once skipped",
			want:   "protocol/record.proto: Stray is sealed false",
			mutate: addMessage(record),
		},
		{
			name:   "a message nobody has walked, in a file it read",
			want:   "protocol/gkm.proto: Stray is sealed false",
			mutate: addMessage(gkm),
		},
		{
			name: "a new file, which the walk would otherwise never open",
			want: "protocol/stray.proto is neither walked nor left to another account",
			mutate: func(fileProtos testFileProtos) {
				fileProtos["protocol/stray.proto"] = &descriptorpb.FileDescriptorProto{
					Name:    proto.String("protocol/stray.proto"),
					Package: proto.String(testProtoPackage),
					Syntax:  proto.String("proto3"),
				}
			},
		},
	}
	rowTexts := testReadRows(t)
	// The rebuild alone must differ in nothing, or every case below would pass for the wrong reason.
	if differences := testWalkDifferences(testPlantedFiles(t, func(testFileProtos) {}), rowTexts); len(differences) != 0 {
		t.Fatalf("the unplanted copy differs: %v", differences)
	}
	for _, c := range cases {
		differences := testWalkDifferences(testPlantedFiles(t, c.mutate), rowTexts)
		if !testHasDifference(differences, c.want) {
			t.Errorf("%s: wanted %q, found %v", c.name, c.want, differences)
		}
	}

	// A row gone, withdrawn or reworded is as good as no row.
	rowCases := []struct {
		name   string
		want   string
		mutate func(rowTexts map[string]string)
	}{
		{
			name:   "a row gone",
			want:   "cites row sock-2, which §2.8 does not hold",
			mutate: func(rowTexts map[string]string) { delete(rowTexts, "sock-2") },
		},
		{
			name:   "a row withdrawn",
			want:   "cites row gkm-7, which is withdrawn",
			mutate: func(rowTexts map[string]string) { rowTexts["gkm-7"] = "  withdrawn: planted\n" },
		},
		{
			name:   "a row reworded",
			want:   "row api-10 no longer says",
			mutate: func(rowTexts map[string]string) { rowTexts["api-10"] = "  sees: planted\n" },
		},
	}
	for _, c := range rowCases {
		changed := maps.Clone(rowTexts)
		c.mutate(changed)
		differences := testWalkDifferences(protoregistry.GlobalFiles, changed)
		if !testHasDifference(differences, c.want) {
			t.Errorf("%s: wanted %q, found %v", c.name, c.want, differences)
		}
	}
}
