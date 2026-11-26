//go:build !ios_extension

// Team's documents (ACL-M6-01; D-ACL-2, D-ACL-23, R-ACL-3, R-ACL-11; owner decisions 40, 74, 126, 179, 180, 344):
//
//	start        D-ACL-2 makes a tier's defaults a starting document. Team's, acl_team_start.hujson, holds §8.5's
//	             grant 1 with plan-ACL-team-grant1-src's src and its via, autogroup:self, so a member's devices route
//	             through each other as well as dial each other (owner decision 344), R-ACL-3's tag:recurd default,
//	             owned by every member so a member's agents may carry it, and the implicit document's last rule, the
//	             team directory's reach requests with autogroup:dst-owner. The first Owner's device saves it as the
//	             network's first document through AclSave (acl_save.go's SaveAclTeamStart), so has_document holds
//	             from then on; a Team narrows any rule, gives one two approvers or removes it as its own document, the
//	             starting one never written again
//	features     the rules an authorization feature adds (DESIGN-COMPUTE §16.5's Team column) stand in the source
//	             between a line "// +<feature>" and a line "// -<feature>", and the document a writer saves holds them
//	             only where its head turns that feature on (AclTeamStartDocumentFor), the marker lines never, so a Team
//	             a release creates before a feature is on saves a document every reader compiles, as the compile
//	             refuses the feature's forms until then: agent_repos' deposit of autogroup:member into every agent repo,
//	             evs:kind:agent (QD-1433), which a Team narrows per agent
//	approvers    a requests rule's approvers: 2 lights up on Team: ACL-M2-07's quorum counts k, and validation takes
//	             it only under acl_approvers_two
//	scope hosts  Q-TLS-3's <host>.<scope> and *.<scope> as dns: hosts, the matching tls/<port>/ names and
//	             smtp/25/mx.<scope>: rows keep the glob (QD-410) and *.<scope> covers one scope's hosts and no other;
//	             validation takes a scope host only for a scope the network's Team scopes hold, so a scope label is
//	             never a client name (§7.7); and a member scope's host takes only its member's consented devices
//	             (§13.9, owner decision 126), which MayPublishInScope and MayListenInScope add to the grant
//	SCIM         group:<name>@<domain> parses and validates with no groups entry, its members SCIM's (§7.6)
//
// Team documents may name autogroup:dst-owner as an approver, as the starting one does.

package sidecar

import (
	"bytes"
	_ "embed"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

//go:embed acl_team_start.hujson
var aclTeamStartSource []byte

// Team's starting document as a head that turns on no authorization feature takes it, a copy:
// AclTeamStartDocumentFor(0).
func AclTeamStartDocument() []byte {
	return AclTeamStartDocumentFor(0)
}

// Team's starting document for a head whose ServiceSettings turns on features: each feature's block kept where features
// holds it and dropped where it does not, the marker lines dropped either way (the file header's features row). A copy.
func AclTeamStartDocumentFor(features AuthFeature) []byte {
	document, err := aclTeamStartDocumentFor(aclTeamStartSource, features)
	if err != nil {
		// the binary's own source, which acl_team_start_test.go holds to its markers
		panic(err)
	}
	return document
}

// source with each feature block kept or dropped for features: a block opens with a line "// +<feature>" and closes
// with "// -<feature>", one feature's at a time; a marker naming no feature, a block opened twice or left open is an
// error.
func aclTeamStartDocumentFor(source []byte, features AuthFeature) ([]byte, error) {
	document := []byte{}
	open := AuthFeature(0)
	for _, line := range bytes.SplitAfter(source, []byte("\n")) {
		marker := strings.TrimSpace(string(line))
		if name, opens := strings.CutPrefix(marker, "// +"); opens {
			feature, err := ParseAuthFeature(name)
			if err != nil || open != 0 {
				return nil, fmt.Errorf("Team's starting document: a block %q opened inside another or naming no feature", marker)
			}
			open = feature
			continue
		}
		if name, closes := strings.CutPrefix(marker, "// -"); closes {
			feature, err := ParseAuthFeature(name)
			if err != nil || feature != open {
				return nil, fmt.Errorf("Team's starting document: a block %q closing none that is open", marker)
			}
			open = 0
			continue
		}
		if open != 0 && features&open == 0 {
			continue
		}
		document = append(document, line...)
	}
	if open != 0 {
		return nil, fmt.Errorf("Team's starting document: %s's block is left open", open)
	}
	return document, nil
}

// The features a head's ServiceSettings turns on, which its compile reads (AclCompileInput.AuthFeatures).
func aclHeadAuthFeatures(head *ConfigHead) (AuthFeature, error) {
	settings, _, err := head.ServiceSettings()
	if err != nil {
		return 0, err
	}
	return AuthFeature(settings.GetAuthFeatures()), nil
}

// One Team scope (§13.8, Q-TLS-3): its label, and for a member scope that member, whose consented devices alone take
// its hosts. A tag scope's MemberId is zero.
type AclScope struct {
	Label    string
	MemberId Id
	TagId    Id
}

// The binding in this verified base. A removed member's label never becomes a tag scope.
func (self *ConfigState) TeamScope(label string) (AclScope, bool) {
	if self == nil {
		return AclScope{}, false
	}
	i, ok := slices.BinarySearchFunc(self.teamScopes, label, func(row *bridge.TeamScopeRow, text string) int {
		return strings.Compare(row.GetLabel(), text)
	})
	if !ok {
		return AclScope{}, false
	}
	row := self.teamScopes[i]
	scope := AclScope{Label: row.GetLabel()}
	if len(row.GetMemberId()) != 0 {
		scope.MemberId = Id(row.GetMemberId())
	} else {
		scope.TagId = Id(row.GetTagAtom())
	}
	return scope, true
}

// All the labels reserved by this verified base, including those whose member is no longer standing.
func (self *ConfigState) TeamScopeLabels() []string {
	if self == nil {
		return nil
	}
	labels := make([]string, 0, len(self.teamScopes))
	for _, scope := range self.teamScopes {
		labels = append(labels, scope.GetLabel())
	}
	return labels
}

// The scope whose signed member or tag owns this device. Multiple matches return an
// empty binding with found true so a caller cannot mistake ambiguity for an unscoped device.
// Consent and eligibility at the requested time are checked by the caller.
func (self *ConfigState) TeamScopeForDevice(sidecarId Id) (AclScope, bool) {
	if self == nil {
		return AclScope{}, false
	}
	device := self.Sidecar(sidecarId)
	if device == nil {
		return AclScope{}, false
	}
	var matched AclScope
	for _, row := range self.teamScopes {
		scope := AclScope{Label: row.GetLabel()}
		if member := row.GetMemberId(); len(member) != 0 {
			scope.MemberId = Id(member)
			if scope.MemberId != device.MemberId {
				continue
			}
		} else {
			scope.TagId = Id(row.GetTagAtom())
			if !slices.Contains(device.TagIds, scope.TagId) {
				continue
			}
		}
		if matched.Label != "" {
			return AclScope{}, true
		}
		matched = scope
	}
	return matched, matched.Label != ""
}

// The scope a host names, false for a host of no scope: <label>.<scope>, two labels, the second the scope.
func aclScopeOfHost(host string) (string, bool) {
	label, scope, found := strings.Cut(host, ".")
	if !found || label == "" || scope == "" || strings.Contains(scope, ".") {
		return "", false
	}
	return scope, true
}

// The host a tls/ or smtp/ socket name names, false for another name: its third segment.
func aclSocketHost(name string) (string, bool) {
	segments := strings.Split(name, "/")
	if len(segments) != 3 || (segments[0] != "tls" && segments[0] != "smtp") {
		return "", false
	}
	return segments[2], true
}

// MayPublish in a Team scope: a member scope's host takes only its member's consented devices, whatever the grants
// say; a tag scope's takes what the grant gives.
func (self *AclState) MayPublishInScope(subject AclSubject, host string, scope AclScope, now time.Time) AclDecision {
	decision := self.MayPublish(subject, host, now)
	if !decision.Allowed {
		return decision
	}
	return self.inScope(subject, scope, decision)
}

// MayListen on a scope host's tls/ or smtp/ name, held to its member scope as MayPublishInScope is.
func (self *AclState) MayListenInScope(subject AclSubject, socket AclSocketName, scope AclScope, now time.Time) AclDecision {
	decision := self.MayListen(subject, socket, now)
	if !decision.Allowed {
		return decision
	}
	return self.inScope(subject, scope, decision)
}

// decision, or unconsented for a subject that is no consented device of a member scope's member.
func (self *AclState) inScope(subject AclSubject, scope AclScope, decision AclDecision) AclDecision {
	if scope.MemberId == (Id{}) {
		return decision
	}
	if subject.Kind != AclSubjectSidecar || !self.ConsentedFor(subject.Id, scope.MemberId) {
		return aclDeny(AclReasonUnconsented)
	}
	return decision
}
