//go:build !ios_extension

// SCIM's queue as the indexer ServiceSettings.scim_signer names reads it (QD-829; §7.6, D-TEAM-25): GET
// /sidecar/scim-changes through the sidecar's own api, with its client token, a route on §7.4's strict_exp allowlist
// beside the other /sidecar/* routes. api answers it only to the client of the sidecar the newest projection's
// ProjectionSettings.scim_signer names, standing, and only with the queued member_revoke changes of the members those
// rows hold outside the AdminSet, oldest first, in the form GET /network/scim-changes gives them (server's
// model.NetworkScimChange); any other client token is refused 403. GET /network/scim-changes stays the console's and
// ur admin's.
//
// What api answers is its unsigned word, used for nothing but which members a MemberRevoke may name (config_scim_signer.go
// says why that is a denial only): an answer that is not the route's shape, a change of another kind, one with no
// member, or change ids out of order, is ErrSidecarApiReply, and the pass that read it signs nothing.
//
// Root Id, no connect type.

package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// The route as errors name it.
const sidecarScimChangesRoute = "GET /sidecar/scim-changes"

// The kind of a queued change that asks for a member's MemberRevoke (server's model.NetworkScimChangeKindMemberRevoke),
// the one kind GET /sidecar/scim-changes answers.
const ScimChangeKindMemberRevoke = "member_revoke"

// One queued change as GET /sidecar/scim-changes answers it: GET /network/scim-changes's form.
type ScimChange struct {
	ChangeId  Id  `json:"change_id"`
	NetworkId Id  `json:"network_id"`
	MemberId  *Id `json:"member_id,omitempty"`
	// ScimChangeKindMemberRevoke on this route.
	Kind string `json:"kind"`
	// The change as the server normalized it; for a member_revoke, the member's email and its role at the denial, for
	// a person to read. The signer reads nothing here.
	Detail     json.RawMessage `json:"detail,omitempty"`
	CreateTime time.Time       `json:"create_time"`
}

// A page of the queue.
type ScimChanges struct {
	// In change_id order.
	Changes []*ScimChange `json:"changes"`
	// Changes follow the last one: read again after it.
	More bool `json:"more,omitempty"`
}

// GET /sidecar/scim-changes?after=<change_id>&limit=<n> with the jwt as bearer (the file header): the queued removals
// after after, nil from the first, at most limit, non-positive for api's own page. Never on a packet path.
func (self *SidecarApi) ScimChanges(ctx context.Context, after *Id, limit int) (*ScimChanges, error) {
	query := url.Values{}
	if after != nil {
		query.Set("after", after.String())
	}
	if 0 < limit {
		query.Set("limit", strconv.Itoa(limit))
	}
	requestUrl := self.settings.ApiUrl + "/sidecar/scim-changes"
	if 0 < len(query) {
		requestUrl += "?" + query.Encode()
	}
	page := &ScimChanges{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     sidecarScimChangesRoute,
		operation: "scim_changes",
		method:    "GET",
		url:       requestUrl,
		bearer:    true,
	}, nil, page)
	if err != nil {
		return nil, err
	}
	malformed := func(why string) (*ScimChanges, error) {
		return nil, fmt.Errorf("sidecar api %s: %w: %s", sidecarScimChangesRoute, ErrSidecarApiReply, why)
	}
	previous := after
	for _, change := range page.Changes {
		switch {
		case change == nil || change.ChangeId == (Id{}):
			return malformed("a change with no id")
		case change.Kind != ScimChangeKindMemberRevoke:
			return malformed("a change of another kind")
		case change.MemberId == nil || *change.MemberId == (Id{}):
			return malformed("a removal naming no member")
		case previous != nil && change.ChangeId.Cmp(*previous) <= 0:
			return malformed("changes out of order")
		}
		previous = &change.ChangeId
	}
	if page.More && len(page.Changes) == 0 {
		// a reader would ask again after the same id forever
		return malformed("more with an empty page")
	}
	return page, nil
}

// SCIM's queue over GET /sidecar/scim-changes through api: ScimChangeSource. Safe for concurrent use.
type sidecarApiScimChangeSource struct {
	api      *SidecarApi
	settings *ConfigScimSignerSettings
}

// The queue's source through api, its page size and page count settings', nil for the defaults.
func newSidecarApiScimChangeSource(api *SidecarApi, settings *ConfigScimSignerSettings) *sidecarApiScimChangeSource {
	if settings == nil {
		settings = DefaultConfigScimSignerSettings()
	}
	return &sidecarApiScimChangeSource{api: api, settings: settings}
}

// SCIM's queue through this Sidecar's own api and client token (the file header): what the daemon installs where this
// sidecar is the one ServiceSettings.scim_signer names, which a ConfigScimSigner reads. settings nil for the defaults.
func (self *Sidecar) NewScimChangeSource(settings *ConfigScimSignerSettings) ScimChangeSource {
	return newSidecarApiScimChangeSource(self.sidecarApi, settings)
}

// The members of the queue's removals, each once, oldest first by its first change: page after page, at most
// PassPageMaxCount of them. Any page's failure fails the read, so a pass never acts on part of an answer it could not
// read whole.
func (self *sidecarApiScimChangeSource) ScimMemberRevokes(ctx context.Context) ([]Id, error) {
	memberIds := []Id{}
	listed := map[Id]bool{}
	var after *Id
	for range max(self.settings.PassPageMaxCount, 1) {
		page, err := self.api.ScimChanges(ctx, after, self.settings.PageCount)
		if err != nil {
			return nil, err
		}
		for _, change := range page.Changes {
			if memberId := *change.MemberId; !listed[memberId] {
				listed[memberId] = true
				memberIds = append(memberIds, memberId)
			}
		}
		if !page.More {
			break
		}
		after = &page.Changes[len(page.Changes)-1].ChangeId
	}
	return memberIds, nil
}
