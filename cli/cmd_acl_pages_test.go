// QD-1162's member-directory pages: ur acl push reads a member past the first page by a page command of its own, whose
// signed body names the member_id it reads after and nothing of the policy, each page its own one-command
// authorization, the first with no body as ur admin members'; it stops at the settings' page bound, and refuses a page
// out of member_id order or one that holds no member while more are said to follow; and ur admin members list
// --after reads the page past a member the same way. Synthetic values only.

package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// Member ids in member_id order, as api pages them.
func testUrAclMemberIds(count int) []sidecar.Id {
	ids := make([]sidecar.Id, 0, count)
	for range count {
		ids = append(ids, sidecar.NewId())
	}
	slices.SortFunc(ids, sidecar.Id.Cmp)
	return ids
}

// A page of rows, each {member_id, email}, and whether more follow.
func testUrAclMemberPage(t *testing.T, more bool, rows ...[2]string) string {
	t.Helper()
	members := []map[string]any{}
	for _, row := range rows {
		members = append(members, map[string]any{"member_id": row[0], "email": row[1]})
	}
	encoded, err := json.Marshal(map[string]any{"members": members, "more": more})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// The after member_id a page command's body names, empty for a command with no body.
func testUrAclMemberPageAfter(t *testing.T, command *sidecar.AdminCommand) string {
	t.Helper()
	if command.Method != "GET" || command.Path != "/network/members" {
		t.Fatalf("a directory read ran %s %s", command.Method, command.Path)
	}
	if len(command.Body) == 0 {
		return ""
	}
	body := map[string]string{}
	if err := json.Unmarshal(command.Body, &body); err != nil || len(body) != 1 || body["after"] == "" {
		t.Fatalf("a page command's body %s", command.Body)
	}
	return body["after"]
}

// A member on the second page is read by a second command, its body the first page's last member_id and nothing else,
// so its consent digest differs from the first's; no command carries an email of the policy's; and a member the first
// page held needs no second.
func TestAclMemberProposalsReadALaterPageByItsOwnCommand(t *testing.T) {
	ids := testUrAclMemberIds(4)
	const wanted, early = "late.member@cli.example", "early.member@cli.example"
	runs := installTestUrAdminRun(t, func(command *sidecar.AdminCommand) string {
		switch testUrAclMemberPageAfter(t, command) {
		case "":
			return testUrAclMemberPage(t, true, [2]string{ids[0].String(), early}, [2]string{ids[1].String(), "other@cli.example"})
		case ids[1].String():
			return testUrAclMemberPage(t, true, [2]string{ids[2].String(), "LATE.member@cli.example"})
		}
		t.Fatalf("a page after %s", command.Body)
		return ""
	})
	cli, stdout, _ := newTestUrCli(filepath.Join(t.TempDir(), "none.sock"))
	members, err := cli.aclMemberProposals(context.Background(), []string{early, wanted})
	if err != nil || members[wanted] != ids[2] || members[early] != ids[0] || len(members) != 2 {
		t.Fatalf("proposals %v, %v", members, err)
	}
	if len(*runs) != 2 || len((*runs)[0].command.Body) != 0 || testUrAclMemberPageAfter(t, (*runs)[1].command) != ids[1].String() {
		t.Fatalf("%d commands", len(*runs))
	}
	first, err := (*runs)[0].command.Digest()
	if err != nil {
		t.Fatal(err)
	}
	second, err := (*runs)[1].command.Digest()
	if err != nil || first == second {
		t.Errorf("the pages' commands share a digest: %v", err)
	}
	for _, run := range *runs {
		if strings.Contains(strings.ToLower(string(run.command.Body)), "cli.example") {
			t.Errorf("a directory request carried an email: %s", run.command.Body)
		}
	}
	if !strings.Contains(stdout.String(), "the next page, after member "+ids[1].String()+", needs its own authorization") {
		t.Errorf("the person was not told of the second authorization: %q", stdout.String())
	}

	*runs = (*runs)[:0]
	if members, err := cli.aclMemberProposals(context.Background(), []string{early}); err != nil || members[early] != ids[0] || len(*runs) != 1 {
		t.Errorf("a first-page member: %v, %v, %d commands", members, err, len(*runs))
	}
}

// The reads stop at the settings' AclMemberPageCount, refusing the email no page read held; a page that repeats the
// cursor, goes back or holds a zero id is refused as out of order; an empty page said to have more after it is
// refused; and a directory with no more pages names the member it holds none of.
func TestAclMemberProposalsRefuseUnboundedOrDisorderedPages(t *testing.T) {
	ids := testUrAclMemberIds(8)
	const wanted = "missing@cli.example"
	cli, _, _ := newTestUrCli(filepath.Join(t.TempDir(), "none.sock"))
	cli.settings.AclMemberPageCount = 3
	pages := 0
	runs := installTestUrAdminRun(t, func(command *sidecar.AdminCommand) string {
		testUrAclMemberPageAfter(t, command)
		pages += 1
		return testUrAclMemberPage(t, true, [2]string{ids[pages].String(), "someone@cli.example"})
	})
	if _, err := cli.aclMemberProposals(context.Background(), []string{wanted}); err == nil || !strings.Contains(err.Error(), "none of the 3 member pages") || len(*runs) != 3 {
		t.Errorf("the page bound: %v, %d commands", err, len(*runs))
	}

	for name, page := range map[string]func(after string) string{
		"a repeated page": func(after string) string {
			return testUrAclMemberPage(t, true, [2]string{ids[1].String(), "someone@cli.example"})
		},
		"a page going back": func(after string) string {
			if after == "" {
				return testUrAclMemberPage(t, true, [2]string{ids[3].String(), "someone@cli.example"})
			}
			return testUrAclMemberPage(t, true, [2]string{ids[2].String(), "someone@cli.example"})
		},
		"a zero id": func(after string) string {
			return testUrAclMemberPage(t, true, [2]string{sidecar.Id{}.String(), wanted})
		},
		"an empty page with more": func(after string) string {
			return testUrAclMemberPage(t, true)
		},
	} {
		runs := installTestUrAdminRun(t, func(command *sidecar.AdminCommand) string {
			return page(testUrAclMemberPageAfter(t, command))
		})
		if members, err := cli.aclMemberProposals(context.Background(), []string{wanted}); err == nil || len(members) != 0 || 3 <= len(*runs) {
			t.Errorf("%s: %v, %v, %d commands", name, members, err, len(*runs))
		}
	}

	installTestUrAdminRun(t, func(command *sidecar.AdminCommand) string {
		return testUrAclMemberPage(t, false, [2]string{ids[1].String(), "someone@cli.example"})
	})
	if _, err := cli.aclMemberProposals(context.Background(), []string{wanted}); err == nil || !strings.Contains(err.Error(), "holds no active member") {
		t.Errorf("the last page: %v", err)
	}
}

// ur admin members list --after reads the page past that member by a command whose signed body names it, and says how
// to read the page after its own; with no --after it reads the first page with no body; an --after that is no member_id
// runs nothing.
func TestAdminMembersListReadsALaterPage(t *testing.T) {
	ids := testUrAclMemberIds(3)
	runs := installTestUrAdminRun(t, func(command *sidecar.AdminCommand) string {
		if testUrAclMemberPageAfter(t, command) == "" {
			return testUrAclMemberPage(t, true, [2]string{ids[0].String(), "first@cli.example"})
		}
		return testUrAclMemberPage(t, true, [2]string{ids[2].String(), "third@cli.example"})
	})
	cli, stdout, _ := newTestUrCli("")
	if code := cli.main(context.Background(), []string{"ur", "admin", "members", "list"}); code != urExitOk || len((*runs)[0].command.Body) != 0 ||
		!strings.Contains(stdout.String(), "ur admin members list --after="+ids[0].String()) {
		t.Fatalf("the first page: exit %d, %q", code, stdout.String())
	}
	stdout.Reset()
	if code := cli.main(context.Background(), []string{"ur", "admin", "members", "list", "--after=" + ids[1].String()}); code != urExitOk ||
		testUrAclMemberPageAfter(t, (*runs)[1].command) != ids[1].String() || !strings.Contains(stdout.String(), "third@cli.example") ||
		!strings.Contains(stdout.String(), "--after="+ids[2].String()) {
		t.Fatalf("a later page: exit %d, %q", code, stdout.String())
	}
	if code := cli.main(context.Background(), []string{"ur", "admin", "members", "list", "--after=not-an-id"}); code == urExitOk || len(*runs) != 2 {
		t.Errorf("a bad --after: exit %d, %d commands", code, len(*runs))
	}
}
