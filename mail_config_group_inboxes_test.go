// The mailcfg classification required to release an ordinary file repo's rcpt directory to MCP.
package sidecar

import (
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// An incomplete address table never certifies that a general repo is an ordinary file repo.
func TestMailGroupInboxesRequireCompleteAddressRecords(t *testing.T) {
	groupId := NewId()
	config := &MailConfig{addressEntries: map[string]*mailConfigEntry{
		"team": {standing: true, record: &mailConfigRecord{mailboxRepoId: groupId, address: &protocol.MailAddress{Kind: protocol.MailAddressKind_MAIL_ADDRESS_GROUP}}},
	}}
	if _, err := config.groupInboxes(); !errors.Is(err, ErrMailConfigNotSynced) {
		t.Fatalf("unverified table: %v", err)
	}
	config.synced = true
	groups, err := config.groupInboxes()
	if err != nil || len(groups) != 1 || !groups[groupId] {
		t.Fatalf("complete table: %v, %v", groups, err)
	}
	config.addressEntries["unreadable"] = &mailConfigEntry{unreadable: true}
	if _, err := config.groupInboxes(); !errors.Is(err, ErrMailConfigNotSynced) {
		t.Fatalf("partially readable table: %v", err)
	}
}
