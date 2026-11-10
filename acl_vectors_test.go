// §22.7's one definition: a file compiles to the same rows on every compiler. Fixed vectors in testdata/acl/vectors,
// for an untagged sidecar and for has_document = false, each built from a world this file fixes and checked byte for
// byte on every §4.7 leg, the Worker's included, which reads them embedded. Each vector names the rows it pins, so a
// format change shows which clause moved before it shows that the whole moved.
//
// go test -run TestAclVectors -acl-write-vectors rewrites them, which only a format change may do.

package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"strconv"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var aclWriteVectors = flag.Bool("acl-write-vectors", false, "rewrite testdata/acl/vectors from this file's worlds")

// One vector file.
type aclVector struct {
	Name       string         `json:"name"`
	Pins       []aclVectorPin `json:"pins"`
	Rows       string         `json:"rows"`
	RowsSha256 string         `json:"rows_sha256"`
}

// One row a vector pins: which, the clause it pins, and its bytes.
type aclVectorPin struct {
	Row    string `json:"row"`
	Clause string `json:"clause"`
	Hex    string `json:"hex"`
}

// A pinned row before it is encoded.
type aclVectorPinned struct {
	row     string
	clause  string
	message proto.Message
}

// Each vector's world, compiled, and the rows it pins.
func aclVectorWorlds(t testing.TB) map[string]func() (*protocol.AclRows, []aclVectorPinned) {
	return map[string]func() (*protocol.AclRows, []aclVectorPinned){
		"untagged_sidecar": func() (*protocol.AclRows, []aclVectorPinned) {
			world := newAclCompileWorld("vector untagged sidecar")
			owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
			world.device("owner laptop", owner)
			world.repo("notes", protocol.RepoKind_REPO_KIND_GENERAL, Id{})
			world.setPolicy(t, `{"grants": [
  {"src": ["autogroup:member"], "dst": ["autogroup:self"], "allow": ["dial", "route"]},
  {"src": ["user:owner@acme.example"], "dst": ["evs:notes"], "allow": ["write"]},
  {"src": ["autogroup:member"], "dst": ["sock:db"], "allow": ["dial"], "ip": ["tcp:5432"]}]}`)
			rows := world.compile(t)
			pins := []aclVectorPinned{}
			for i, atom := range rows.GetAtoms() {
				pins = append(pins, aclVectorPinned{row: "atoms[" + strconv.Itoa(i) + "]", clause: "user: compiles to its member's derived atom (plan-ACL-nonsidecar-subjects)", message: atom})
			}
			for i, rule := range rows.GetRules() {
				clause := map[Id]string{
					world.documentRuleId(t, "grant", 0): "autogroup:self dial and route among an owner's devices (§8.4)",
					world.documentRuleId(t, "grant", 1): "evs:<label> through the labels file, write (§8.4)",
					world.documentRuleId(t, "grant", 2): "sock: as its token path, ports_limited and no port (plan-BRIDGE-gate-row-prefixes #1)",
				}[Id(rule.GetRuleId())]
				pins = append(pins, aclVectorPinned{row: "rules[" + strconv.Itoa(i) + "]", clause: clause, message: rule})
			}
			for i, repo := range rows.GetRepos() {
				pins = append(pins, aclVectorPinned{row: "repos[" + strconv.Itoa(i) + "]", clause: "the log's repo rows ride as folded", message: repo})
			}
			return rows, pins
		},
		"no_document": func() (*protocol.AclRows, []aclVectorPinned) {
			world := newAclCompileWorld("vector no document")
			owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
			world.device("owner laptop", owner)
			world.agent("agent", owner, "worker")
			rows := world.compile(t)
			clauses := []string{
				"implicit grant 1: autogroup:member and autogroup:untagged, * and every action (owner decision 105)",
				"implicit grant 2: autogroup:member writes and administers evs:*",
				"implicit grant 3: autogroup:tagged deposits to evs:*",
				"implicit grant 4: autogroup:tagged dials autogroup:self on tcp:443, ports_limited",
				"implicit request 1: publishes and tls/, smtp/ listens for autogroup:network, admin-approved, 7 d (§13.9)",
				"implicit request 2: autogroup:tagged's self-approved reach, 30 d (owner decision 74)",
				"implicit request 3: network:* shares, admin-approved (§8.11)",
				"implicit request 4: the directory's dial requests, autogroup:dst-owner, device or presence (D-ACL-23)",
			}
			pins := []aclVectorPinned{}
			for i, rule := range rows.GetRules() {
				for index := range uint32(4) {
					if Id(rule.GetRuleId()) == aclImplicitRuleId(index) {
						pins = append(pins, aclVectorPinned{row: "rules[" + strconv.Itoa(i) + "]", clause: clauses[index], message: rule})
					}
				}
			}
			for i, request := range rows.GetRequests() {
				for index := uint32(4); index < 8; index += 1 {
					if Id(request.GetRuleId()) == aclImplicitRuleId(index) {
						pins = append(pins, aclVectorPinned{row: "requests[" + strconv.Itoa(i) + "]", clause: clauses[index], message: request})
					}
				}
			}
			return rows, pins
		},
	}
}

// Every vector compiles to its file's bytes, each pinned row first, then the whole.
func TestAclVectors(t *testing.T) {
	encode := proto.MarshalOptions{Deterministic: true}
	for name, build := range aclVectorWorlds(t) {
		rows, pinned := build()
		rowsBytes, err := encode.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		vector := aclVector{Name: name, Rows: hex.EncodeToString(rowsBytes)}
		digest := sha256.Sum256(rowsBytes)
		vector.RowsSha256 = hex.EncodeToString(digest[:])
		for _, pin := range pinned {
			pinBytes, err := encode.Marshal(pin.message)
			if err != nil {
				t.Fatal(err)
			}
			vector.Pins = append(vector.Pins, aclVectorPin{Row: pin.row, Clause: pin.clause, Hex: hex.EncodeToString(pinBytes)})
		}
		path := "testdata/acl/vectors/" + name + ".json"
		if *aclWriteVectors {
			data, err := json.MarshalIndent(vector, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		data, err := testAclVectorFiles.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := aclVector{}
		if err := json.Unmarshal(data, &want); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(want.Pins) != len(vector.Pins) {
			t.Errorf("%s pins %d rows, and compiles %d", name, len(want.Pins), len(vector.Pins))
		}
		for i := range min(len(want.Pins), len(vector.Pins)) {
			if want.Pins[i].Row != vector.Pins[i].Row || want.Pins[i].Hex != vector.Pins[i].Hex {
				t.Errorf("%s: %s moved: %s", name, want.Pins[i].Row, want.Pins[i].Clause)
			}
		}
		if want.Rows != vector.Rows || want.RowsSha256 != vector.RowsSha256 {
			t.Errorf("%s compiles to other rows", name)
		}
	}
}
