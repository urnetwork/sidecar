//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

// Inputs held by the writer's host. Members are email proposals from its own accepted
// invite records or an Owner/Admin read of GET /network/members, never an admission.
// Networks are this instance's enrolled networks, used only for §12 label resolution.
type AclWriterSubjects struct {
	Members  map[string]Id
	Networks []*Sidecar
}

// The writer needs a member-directory proposal for these policy emails before it can preview.
type AclMemberLookupRequired struct {
	Emails []string
}

// Canonical email selectors, including those in groups, requests and policy tests.
func (self *AclPolicy) MemberEmails() []string {
	return slices.Sorted(maps.Keys(aclSaveNamesOf(self).users))
}

func (self *AclMemberLookupRequired) Error() string {
	return "the writer needs an Owner or Admin member-directory read to resolve the policy's emails"
}

type aclWriterSubjectResolver struct {
	writer       *Sidecar
	state        *ConfigState
	subjects     *AclWriterSubjects
	root         string
	labels       *NetworkLabelTable
	unreadLabels error
}

func (self *aclWriterSubjectResolver) ResolveMember(ctx context.Context, email string) (Id, bool, error) {
	memberId, ok := self.subjects.Members[email]
	if !ok || memberId == (Id{}) || self.state.Member(memberId) == nil {
		return Id{}, false, fmt.Errorf("%w: %s has no live member in the signed network state", ErrAclPolicyInvalid, email)
	}
	return memberId, true, nil
}

// The same root and lookup mode as a policy or .ur: labels, live aliases and retiring aliases.
// A legacy network name and a DNS answer for another enrollment never enter the table.
func (self *aclWriterSubjectResolver) ResolveNetwork(ctx context.Context, text string) (Id, bool, error) {
	if self.labels == nil {
		table := &NetworkLabelTable{}
		networks := slices.Clone(self.subjects.Networks)
		if !slices.Contains(networks, self.writer) {
			networks = append(networks, self.writer)
		}
		for _, running := range networks {
			if running == nil {
				return Id{}, false, errors.New("the writer was given a missing network enrollment")
			}
			row, err := aclWriterNetworkLabel(ctx, running)
			if err != nil {
				if running == self.writer {
					return Id{}, false, err
				}
				self.unreadLabels = err
				continue
			}
			if running == self.writer {
				self.root = row.Root
			}
			table.rows = append(table.rows, row)
		}
		if err := checkNetworkLabelRows(table.rows); err != nil {
			return Id{}, false, err
		}
		self.labels = table
	}
	id, kind, err := self.labels.ResolveNetworkLabel(self.root, text, false)
	// Fresh labels and aliases are unique under the root. An unrelated unavailable
	// enrollment cannot contradict one, but a cached retiring alias needs the whole view.
	if self.unreadLabels != nil && (errors.Is(err, ErrNetworkLabelUnknown) || kind == NetworkLabelKindRetiringAlias) {
		return Id{}, false, self.unreadLabels
	}
	return id, err == nil, err
}

func aclWriterNetworkLabel(ctx context.Context, running *Sidecar) (NetworkLabelRow, error) {
	dns, err := running.Dns()
	if err != nil {
		return NetworkLabelRow{}, err
	}
	zone, err := dns.fetchZone(ctx)
	if err != nil {
		return NetworkLabelRow{}, err
	}
	row, err := canonicalNetworkLabelRow(NetworkLabelRow{Root: zone.Root, NetworkId: zone.NetworkId, Label: zone.Label, Alias: zone.Alias})
	if err != nil {
		return NetworkLabelRow{}, err
	}
	dns.stateLock.Lock()
	registered := dns.labels
	dns.stateLock.Unlock()
	if registered == nil {
		registered, err = OpenNetworkLabelTable(running.LocalStore())
		if err != nil {
			return NetworkLabelRow{}, err
		}
	}
	for _, held := range registered.Networks() {
		if held.Root == row.Root && held.NetworkId == row.NetworkId {
			row.RetiringAliases = held.RetiringAliases
			break
		}
	}
	return row, nil
}

func (self *aclWriterSubjectResolver) ResolveClient(ctx context.Context, clientId Id) (Id, bool, error) {
	if self.writer.sidecarApi == nil {
		return Id{}, false, errors.New("no identity service for the client's binding")
	}
	record, err := self.writer.sidecarApi.GetIdentityByClient(ctx, clientId)
	var refusal *SidecarApiError
	if errors.As(err, &refusal) && refusal.Status == http.StatusNotFound {
		return Id{}, false, nil
	}
	if err != nil {
		return Id{}, false, err
	}
	binding, err := VerifySidecarIdentityBinding(record.Binding)
	if err != nil {
		return Id{}, false, err
	}
	if binding.NetworkId != self.state.NetworkId() || binding.ClientId != clientId || binding.SidecarId != record.SidecarId ||
		!bytes.Equal(binding.IdentityPublicKey, self.state.IdentityKey(binding.SidecarId)) {
		return Id{}, false, fmt.Errorf("%w: client binding differs from its signed network admission", ErrAclPolicyInvalid)
	}
	return binding.SidecarId, true, nil
}

func (self *Sidecar) aclWriterPlan(ctx context.Context, source []byte, subjects *AclWriterSubjects, state *ConfigState, head *ConfigHead) (*AclSavePlan, error) {
	policy, err := ParseAclPolicy(source)
	if err != nil {
		return nil, err
	}
	emails := policy.MemberEmails()
	if subjects == nil {
		// A host with no directory read may keep a previously confirmed binding to a still-live
		// member. Never manufacture a first binding, including for emails used only in tests.
		held := &protocol.ConfigResolution{}
		if err := aclSaveDecode(head, ConfigHeadResolvePath, held); err != nil {
			return nil, err
		}
		subjects = &AclWriterSubjects{Members: map[string]Id{}}
		for _, row := range held.GetMembers() {
			id, err := IdFromBytes(row.GetMemberId())
			if err == nil && state.Member(id) != nil {
				subjects.Members[row.GetEmail()] = id
			}
		}
		for _, email := range emails {
			if _, known := subjects.Members[email]; !known {
				return nil, &AclMemberLookupRequired{Emails: emails}
			}
		}
	} else if subjects.Members == nil && len(emails) > 0 {
		return nil, &AclMemberLookupRequired{Emails: emails}
	}
	resolver := &aclWriterSubjectResolver{writer: self, subjects: subjects, state: state}
	return PlanAclSave(ctx, &AclSaveInput{
		Policy: source, Head: head, State: state, Now: self.clock.Now(), ResolveScope: state.TeamScope, Resolver: resolver,
		ResolveNetworkLabel: func(text string) (Id, bool) {
			id, found, err := resolver.ResolveNetwork(ctx, text)
			return id, found && err == nil
		},
	})
}
