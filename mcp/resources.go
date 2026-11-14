//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's resources and notifications (D-MCP-3, D-MCP-17, I-7, X10; MCP-M3-14): McpResources, the map of the ur://
// resource families the daemon serves, every one subscribable, and the notifications that tell a subscribed session
// one changed. Other plans plug their families in from their own files, as tools register (catalog.go): RECORD-M3-09's
// ur://record/{log}, MCP-M7-01's ur://mail/{alias} and MCP-M3-13's ur://evs/{repo}/{+path}. This file holds the map
// and ur://approval/{id} and ur://acl/grants.
//
//	read       resources/read is a call (server.go's middleware): the network resolved and ready, a policy installed,
//	           then the family's read under the same guard and taint rule as its tool, its data in the envelope a tool
//	           result carries (result.go), as one application/json content, refused when it holds a credential (I-7)
//	subscribe  resources/subscribe goes to the family whose template matches, which judges it at once, so a
//	           subscription on a refused repo refuses at subscribe, never at its first event; a URI no family
//	           matches is not found
//	updated    a change goes out as resources/updated carrying the URI alone, never what changed: each family maps
//	           §6's topics and §11's token-prefix subscriptions to it through Notify, which queues and coalesces, so a
//	           source's callback never waits on a session
//
// progress notifications for long calls are left to the tools that run long (search's phase 2, MCP-M10-02).
//
// Safe for concurrent use; families are added before Install.

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The MIME type of every resource's content: the envelope's JSON.
const mcpResourceMimeType = "application/json"

// One resource family's constant spec.
type McpResourceSpec struct {
	// RFC 6570's form, ur://<family>/..., its variables {name} for one segment and {+name} for the rest.
	UriTemplate string
	Name        string
	// Constant text: no variable ever reaches a resource list (D-MCP-3).
	Description string
	// Reads one URI of the family for the call, as its tool reads: the guard, the taint rule and the result's tags
	// are the family's to apply, through result.
	Read func(ctx context.Context, call *McpCall, uri string, variables map[string]string, result *McpResult) (any, error)
	// Judges a subscription of one URI for the session, at once; nil admits every URI the template matches.
	Subscribe func(ctx context.Context, session *McpSession, uri string, variables map[string]string) error
}

// One part of a template: literal text, or a variable.
type mcpTemplatePart struct {
	literal string
	name    string
	// {+name}: the rest of the URI, slashes included
	rest bool
}

// A family as added: its spec and its template's parts.
type mcpResourceFamily struct {
	spec  *McpResourceSpec
	parts []mcpTemplatePart
}

// The map of resource families a daemon serves.
type McpResources struct {
	server *McpServer

	stateLock sync.Mutex
	families  []*mcpResourceFamily
	installed bool
	// URIs changed and not yet sent, and the wake of the sender
	pending map[string]bool
	wake    chan struct{}
}

// An empty map on server, whose notifications its sender sends until ctx ends.
func NewMcpResources(ctx context.Context, server *McpServer) *McpResources {
	self := &McpResources{server: server, pending: map[string]bool{}, wake: make(chan struct{}, 1)}
	go self.run(ctx)
	return self
}

// A template's parts, or an error for one that is not ur://, leaves a variable unnamed or puts text after {+name}.
func parseMcpTemplate(template string) ([]mcpTemplatePart, error) {
	if !strings.HasPrefix(template, "ur://") {
		return nil, fmt.Errorf("resource template %q: not ur://", template)
	}
	parts := []mcpTemplatePart{}
	rest := template
	for rest != "" {
		open := strings.IndexByte(rest, '{')
		if open < 0 {
			parts = append(parts, mcpTemplatePart{literal: rest})
			break
		}
		if 0 < open {
			parts = append(parts, mcpTemplatePart{literal: rest[:open]})
		}
		close := strings.IndexByte(rest[open:], '}')
		if close < 0 {
			return nil, fmt.Errorf("resource template %q: an unclosed variable", template)
		}
		name := rest[open+1 : open+close]
		part := mcpTemplatePart{name: name}
		if strings.HasPrefix(name, "+") {
			part = mcpTemplatePart{name: name[1:], rest: true}
		}
		if part.name == "" {
			return nil, fmt.Errorf("resource template %q: a variable with no name", template)
		}
		parts = append(parts, part)
		rest = rest[open+close+1:]
		if part.rest && rest != "" {
			return nil, fmt.Errorf("resource template %q: text after {+%s}", template, part.name)
		}
	}
	return parts, nil
}

// The variables of uri under the family's template, each unescaped, false where the template does not match. A
// one-segment variable takes no slash, and none may be empty.
func (self *mcpResourceFamily) match(uri string) (map[string]string, bool) {
	variables := map[string]string{}
	rest := uri
	for i, part := range self.parts {
		if part.name == "" {
			if !strings.HasPrefix(rest, part.literal) {
				return nil, false
			}
			rest = rest[len(part.literal):]
			continue
		}
		value := rest
		if !part.rest {
			end := len(rest)
			if i+1 < len(self.parts) {
				next := strings.Index(rest, self.parts[i+1].literal)
				if next < 0 {
					return nil, false
				}
				end = next
			}
			value = rest[:end]
			if strings.Contains(value, "/") {
				return nil, false
			}
		}
		unescaped, err := url.PathUnescape(value)
		if err != nil || unescaped == "" {
			return nil, false
		}
		variables[part.name] = unescaped
		rest = rest[len(value):]
	}
	if rest != "" {
		return nil, false
	}
	return variables, true
}

// Adds a family. Panics, as a tool's registration does, on a spec that cannot serve: no read, no name or
// description, a bad template, a template taken, or the map installed already.
func (self *McpResources) Add(spec *McpResourceSpec) {
	if spec == nil || spec.Read == nil || spec.Name == "" || spec.Description == "" {
		panic("mcp.McpResources.Add: a spec needs a template, a name, a description and a read")
	}
	parts, err := parseMcpTemplate(spec.UriTemplate)
	if err != nil {
		panic(err.Error())
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.installed {
		panic(fmt.Sprintf("mcp.McpResources.Add %q: the map is installed", spec.UriTemplate))
	}
	for _, family := range self.families {
		if family.spec.UriTemplate == spec.UriTemplate {
			panic(fmt.Sprintf("mcp.McpResources.Add %q: the template is taken", spec.UriTemplate))
		}
	}
	self.families = append(self.families, &mcpResourceFamily{spec: spec, parts: parts})
}

// Every family's template, sorted.
func (self *McpResources) Templates() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	templates := []string{}
	for _, family := range self.families {
		templates = append(templates, family.spec.UriTemplate)
	}
	slices.Sort(templates)
	return templates
}

// The family a URI belongs to and its variables, false for none.
func (self *McpResources) family(uri string) (*mcpResourceFamily, map[string]string, bool) {
	self.stateLock.Lock()
	families := slices.Clone(self.families)
	self.stateLock.Unlock()
	for _, family := range families {
		if variables, ok := family.match(uri); ok {
			return family, variables, true
		}
	}
	return nil, nil, false
}

// Puts every family's template on the server's go-sdk Servers, made already or later, sets the server's subscribe
// check to the map's, and closes the map to more families.
func (self *McpResources) Install() {
	families := func() []*mcpResourceFamily {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.installed = true
		return slices.Clone(self.families)
	}()
	self.server.Install(func(server *gomcp.Server) {
		for _, family := range families {
			family := family
			server.AddResourceTemplate(&gomcp.ResourceTemplate{
				URITemplate: family.spec.UriTemplate,
				Name:        family.spec.Name,
				Description: family.spec.Description,
				MIMEType:    mcpResourceMimeType,
			}, func(ctx context.Context, request *gomcp.ReadResourceRequest) (*gomcp.ReadResourceResult, error) {
				return self.read(ctx, family, request)
			})
		}
	})
	self.server.SetSubscribeCheck(self.subscribe)
}

// A resource the map does not hold, by go-sdk's code, naming nothing of the URI.
func errMcpResourceNotFound() error {
	return &jsonrpc.Error{Code: gomcp.CodeResourceNotFound, Message: "no such resource"}
}

// One read: the family's, under the same checks as a tool's call, its envelope as one JSON content.
func (self *McpResources) read(ctx context.Context, family *mcpResourceFamily, request *gomcp.ReadResourceRequest) (*gomcp.ReadResourceResult, error) {
	call := McpCallOf(ctx)
	if request == nil || request.Params == nil {
		return nil, errMcpResourceNotFound()
	}
	uri := request.Params.URI
	variables, ok := family.match(uri)
	if !ok {
		return nil, errMcpResourceNotFound()
	}
	text, err := mcpReadResource(ctx, family, call, uri, variables)
	if err != nil {
		return nil, mcpWireError(mcpCheckedError(call, err))
	}
	return &gomcp.ReadResourceResult{Contents: []*gomcp.ResourceContents{{URI: uri, MIMEType: mcpResourceMimeType, Text: text}}}, nil
}

// A read's envelope as text: the network with a policy, the family's read under a meter, the result's tags, and the
// secret check (I-7).
func mcpReadResource(ctx context.Context, family *mcpResourceFamily, call *McpCall, uri string, variables map[string]string) (string, error) {
	if call == nil {
		return "", errMcpNoCall
	}
	network, ok := mcpToolNetworkOf(call)
	if !ok {
		return "", errMcpNoToolNetwork
	}
	if network.Identity() == nil || !network.PolicyInstalled() {
		return "", errMcpNoPolicy
	}
	meter := &mcpMeter{}
	result := newMcpResult(call)
	out, err := family.spec.Read(withMcpMeter(ctx, meter), call, uri, variables, result)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(out)
	if err != nil {
		return "", errMcpFailed
	}
	envelope, err := result.envelope(json.RawMessage(data), meter.byteCount.Load())
	if err != nil {
		return "", err
	}
	matcher, err := network.SecretMatcher()
	if err != nil {
		return "", errMcpMatcher
	}
	if matcher.Matches(data) || matcher.Matches([]byte(envelope.Source)) {
		return "", errMcpResultSecret
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", errMcpFailed
	}
	return string(encoded), nil
}

// One subscription: the family whose template matches judges it at once; no family, not found.
func (self *McpResources) subscribe(ctx context.Context, session *McpSession, uri string) error {
	family, variables, ok := self.family(uri)
	if !ok {
		return errMcpResourceNotFound()
	}
	if family.spec.Subscribe == nil {
		return nil
	}
	if err := family.spec.Subscribe(ctx, session, uri, variables); err != nil {
		return mcpWireError(err)
	}
	return nil
}

// Tells every session subscribed to uri that it changed, now: the notification carries the uri alone.
func (self *McpResources) Updated(ctx context.Context, uri string) error {
	return self.server.ResourceUpdated(ctx, uri)
}

// Queues uri's change for the sender, coalescing repeats, and never waits: what a source's callback calls.
func (self *McpResources) Notify(uri string) {
	self.stateLock.Lock()
	self.pending[uri] = true
	self.stateLock.Unlock()
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// The sender: each queued uri's notification, until ctx ends.
func (self *McpResources) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-self.wake:
		}
		uris := func() []string {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			uris := []string{}
			for uri := range self.pending {
				uris = append(uris, uri)
			}
			clear(self.pending)
			slices.Sort(uris)
			return uris
		}()
		for _, uri := range uris {
			if err := self.Updated(ctx, uri); err != nil {
				self.server.log.Warningf("[mcp]a resource's update was not sent: %s", err)
			}
		}
	}
}

// What a resource registration gets: the map, and the daemon's server for what its families read of it.
type McpResourceRegistration func(resources *McpResources, server *McpServer)

// The registrations linked into this build, in the order their files' init ran.
var mcpResourceRegistrations struct {
	stateLock     sync.Mutex
	registrations []McpResourceRegistration
}

// Adds a family owner's registration, which NewDaemonMcpResources runs. Call from the owner's file's init.
func registerMcpResources(registration McpResourceRegistration) {
	mcpResourceRegistrations.stateLock.Lock()
	defer mcpResourceRegistrations.stateLock.Unlock()
	mcpResourceRegistrations.registrations = append(mcpResourceRegistrations.registrations, registration)
}

// The daemon's map: every registration linked into the build, its sender running until ctx ends. Install it on
// server before serving.
func NewDaemonMcpResources(ctx context.Context, server *McpServer) *McpResources {
	resources := NewMcpResources(ctx, server)
	registrations := func() []McpResourceRegistration {
		mcpResourceRegistrations.stateLock.Lock()
		defer mcpResourceRegistrations.stateLock.Unlock()
		return slices.Clone(mcpResourceRegistrations.registrations)
	}()
	for _, registration := range registrations {
		registration(resources, server)
	}
	return resources
}

// The URI of an approval's resource.
func McpApprovalUri(approvalId sidecar.Id) string {
	return "ur://approval/" + approvalId.String()
}

// The URI of the grants resource.
const McpAclGrantsUri = "ur://acl/grants"

// What ur://approval/{id} reads: the network's approval state, *sidecar.Sidecar's.
type mcpApprovalNetwork interface {
	ApprovalStatus(ctx context.Context, approvalId sidecar.Id) (*sidecar.ApprovalStatus, error)
}

// ur://approval/{id}'s data: where one of this sidecar's approvals stands, ids and states only.
type mcpApprovalOut struct {
	ApprovalId string `json:"approval_id"`
	State      string `json:"state"`
	ActionId   string `json:"action_id"`
	Tainted    bool   `json:"tainted"`
	// ms since the epoch
	NotAfterMillis int64    `json:"not_after_millis"`
	Uses           uint32   `json:"uses"`
	UsedCount      int      `json:"used_count"`
	Channels       []string `json:"channels"`
}

// The refusals of the approval resource.
var (
	errMcpApprovalUnknown     = NewMcpError(McpCodeInvalidArguments, "no approval of this sidecar's has that id", false)
	errMcpApprovalUnavailable = NewMcpError(McpCodeUnavailable, "this daemon holds no approval state for the network yet: run ur status in your own terminal", true)
)

// Approval channels by name, as records label them: device, presence or harness.
func mcpChannelName(channel protocol.ApprovalChannel) string {
	return strings.TrimPrefix(strings.ToLower(channel.String()), "approval_channel_")
}

// An approval state's error as the resource answers it, by constant text.
func mcpApprovalError(err error) error {
	switch {
	case errors.Is(err, sidecar.ErrApprovalUnknown):
		return errMcpApprovalUnknown
	case errors.Is(err, sidecar.ErrApprovalNoState):
		return errMcpApprovalUnavailable
	}
	return err
}

// Registers ur://approval/{id} and ur://acl/grants.
func init() {
	registerMcpResources(func(resources *McpResources, server *McpServer) {
		addCoreMcpResources(resources)
	})
}

// The two families of this file.
func addCoreMcpResources(resources *McpResources) {
	resources.Add(&McpResourceSpec{
		UriTemplate: "ur://approval/{id}",
		Name:        "approval",
		Description: "Where one of this sidecar's approvals stands: pending, approved, denied, cancelled, expired, spent or used, with its uses and the evidence of each decision.",
		Read: func(ctx context.Context, call *McpCall, uri string, variables map[string]string, result *McpResult) (any, error) {
			approvalId, err := sidecar.ParseId(variables["id"])
			if err != nil {
				return nil, errMcpApprovalUnknown
			}
			approvals, ok := call.Network.(mcpApprovalNetwork)
			if !ok {
				return nil, errMcpApprovalUnavailable
			}
			result.SetSource("approval:" + approvalId.String())
			status, err := approvals.ApprovalStatus(ctx, approvalId)
			if err != nil {
				return nil, mcpApprovalError(err)
			}
			out := &mcpApprovalOut{
				ApprovalId:     status.ApprovalId.String(),
				State:          string(status.State),
				ActionId:       fmt.Sprintf("%x", status.ActionId),
				Tainted:        status.Tainted,
				NotAfterMillis: status.NotAfter.UnixMilli(),
				Uses:           status.Uses,
				UsedCount:      status.UsedCount,
				Channels:       []string{},
			}
			for _, channel := range status.Channels {
				out.Channels = append(out.Channels, mcpChannelName(channel))
			}
			return out, nil
		},
		Subscribe: func(ctx context.Context, session *McpSession, uri string, variables map[string]string) error {
			if _, err := sidecar.ParseId(variables["id"]); err != nil {
				return errMcpApprovalUnknown
			}
			return nil
		},
	})
	resources.Add(&McpResourceSpec{
		UriTemplate: McpAclGrantsUri,
		Name:        "acl_grants",
		Description: "The grants in force for this sidecar, the network's members and their roles, and its registered keys, as ids: what acl_grants and team_members read, which changes as the config moves.",
		Read: func(ctx context.Context, call *McpCall, uri string, variables map[string]string, result *McpResult) (any, error) {
			return mcpAclGrantsView(call, result)
		},
	})
}

// Watches an approval gate's inbox: each change of an approval goes out as its resource's update.
func (self *McpResources) WatchApprovals(inbox *sidecar.ApprovalInbox) func() {
	return inbox.AddUpdateCallback(func(approvalId sidecar.Id) {
		self.Notify(McpApprovalUri(approvalId))
	})
}

// Watches a network's config: each entry it applies goes out as ur://acl/grants' update, since a grant, a member or a
// key may have changed.
func (self *McpResources) WatchConfig(config *sidecar.ConfigClient) func() {
	return config.AddEntryCallback(func(entry *sidecar.SidecarAuthorityEntry) {
		self.Notify(McpAclGrantsUri)
	})
}
