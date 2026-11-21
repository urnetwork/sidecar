//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's mail resources (MCP-M7-01; D-MCP-13, I-9, I-13), under the same trust and taint rule as their tools
// (tools_mail.go's header):
//
//	address  ur://mail/{alias}: the newest page of one of this network's addresses' messages, as mail_list with that
//	         alias answers it, the address with its @ escaped (McpMailUri), since the template's one-segment variable
//	         takes no reserved character. A subscription is judged at once: the address must be one mailcfg's records
//	         hold. It is leased once per network and URI, for the map's life, on the mail client's hint, which rises at
//	         each message this device's ingest writes, and each rise goes out as the URI's resources/updated, carrying
//	         the URI alone
//	message  ur://mail/{repo}/{month}/{message}: one message as mail_read answers it, read again, so the result an
//	         over-limit mail_read links to (D-MCP-13) holds the same tags and markers; the message must be in the
//	         repo the URI names. A message's bytes never change, so a subscription is admitted and leased on nothing
//
// The attachment links mail_read names, a fourth segment below a message's, are not served here: the client reads no
// part's bytes yet, so their URIs match no family and read as not found.

package mcp

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
)

// Where every mail resource's URI starts.
const mcpMailUriPrefix = "ur://mail/"

// Bytes a URI's segment keeps as they are: RFC 3986's unreserved set, which the template's variables match.
const mcpMailUriUnreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"

// The URI of an address's resource: every byte of the address outside the unreserved set percent-escaped, so its @
// reads %40.
func McpMailUri(address string) string {
	builder := strings.Builder{}
	builder.WriteString(mcpMailUriPrefix)
	for _, b := range []byte(address) {
		if strings.IndexByte(mcpMailUriUnreserved, b) < 0 {
			fmt.Fprintf(&builder, "%%%02X", b)
			continue
		}
		builder.WriteByte(b)
	}
	return builder.String()
}

// The URI of one message's resource, which an over-limit mail_read names: ids only (I-13).
func McpMailMessageUri(repoId sidecar.Id, month sidecar.MailYearMonth, messageId sidecar.Id) string {
	return mcpMailUriPrefix + repoId.String() + "/" + month.String() + "/" + messageId.String()
}

// The refusal of a subscription to an address this network holds no record of.
var errMcpMailAddressUnknown = NewMcpError(McpCodeInvalidArguments, "no address of this network has that name: mail_aliases names them", false)

// The leases of subscribed ur://mail addresses, one per network and URI, each kept for the map's life: unsubscribe
// reaches no family, so a URI's lease outlives its sessions, and each change still sends only its URI.
type mcpMailLeases struct {
	stateLock sync.Mutex
	leased    map[mcpEvsLeaseKey]bool
}

// Leases uri's notifications on client's hint once for networkId, each rise of the hint notifying uri until the map
// ends.
func (self *mcpMailLeases) lease(resources *McpResources, networkId sidecar.Id, uri string, client McpMailClient) {
	key := mcpEvsLeaseKey{networkId: networkId, uri: uri}
	taken := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.leased[key] {
			return false
		}
		self.leased[key] = true
		return true
	}()
	if !taken {
		return
	}
	ctx := resources.context()
	revision, changed := client.ImapHints()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-changed:
			}
			// subscribe and read in one step, the monitor's pair, so no rise between them is lost
			next, nextChanged := client.ImapHints()
			if next != revision {
				revision = next
				resources.Notify(uri)
			}
			changed = nextChanged
		}
	}()
}

func init() {
	registerMcpResources(func(resources *McpResources, server *McpServer) {
		addMailResources(resources, server)
	})
}

// The month and message id of a message resource's variables.
func mcpMailMessageVariables(variables map[string]string) (sidecar.Id, sidecar.MailYearMonth, sidecar.Id, error) {
	repoId, err := sidecar.ParseId(variables["repo"])
	if err != nil || repoId == (sidecar.Id{}) {
		return sidecar.Id{}, 0, sidecar.Id{}, errMcpResourceNotFound()
	}
	month, messageId, err := mcpMailParseId(variables["month"] + "/" + variables["message"])
	if err != nil {
		return sidecar.Id{}, 0, sidecar.Id{}, errMcpResourceNotFound()
	}
	return repoId, month, messageId, nil
}

// Adds the two mail families to resources, their subscriptions resolved through server.
func addMailResources(resources *McpResources, server *McpServer) {
	leases := &mcpMailLeases{leased: map[mcpEvsLeaseKey]bool{}}
	resources.Add(&McpResourceSpec{
		UriTemplate: "ur://mail/{alias}",
		Name:        "mail",
		Description: "The newest messages to one of this network's addresses, as mail_list answers them; outside mail comes back marked untrusted, and reading it taints the run.",
		Read: func(ctx context.Context, call *McpCall, uri string, variables map[string]string, result *McpResult) (any, error) {
			client, err := mcpMailClientOf(call)
			if err != nil {
				return nil, err
			}
			ctx = mcpMailReadContext(ctx, call)
			page, err := client.ListAddress(ctx, variables["alias"], &sidecar.MailListArgs{Folder: sidecar.MailFolderAll})
			if err != nil {
				return nil, mcpMailReadError(err)
			}
			if page == nil {
				page = &sidecar.MailListPage{}
			}
			return mcpMailPage(ctx, call, page, false, "mail:list", result)
		},
		Subscribe: func(ctx context.Context, session *McpSession, uri string, variables map[string]string) error {
			networkId, network, err := server.sessionNetwork(session, "")
			if err != nil {
				return err
			}
			mail, ok := network.(McpMailNetwork)
			if !ok {
				return errMcpMailUnavailable
			}
			if mail.Identity() == nil || !mail.PolicyInstalled() {
				return errMcpNoPolicy
			}
			client, err := mail.McpMail()
			if err != nil || client == nil {
				return errMcpMailUnavailable
			}
			lookups, err := client.Aliases(ctx)
			if err != nil {
				return mcpMailReadError(err)
			}
			address := strings.ToLower(variables["alias"])
			known := false
			for _, lookup := range lookups {
				if lookup != nil && strings.ToLower(lookup.Address) == address {
					known = true
				}
			}
			if !known {
				return errMcpMailAddressUnknown
			}
			leases.lease(resources, networkId, uri, client)
			return nil
		},
	})
	resources.Add(&McpResourceSpec{
		UriTemplate: "ur://mail/{repo}/{month}/{message}",
		Name:        "mail_message",
		Description: "One message as mail_read answers it, which an over-limit mail_read result names; outside mail comes back marked untrusted, and reading it taints the run.",
		Read: func(ctx context.Context, call *McpCall, uri string, variables map[string]string, result *McpResult) (any, error) {
			repoId, month, messageId, err := mcpMailMessageVariables(variables)
			if err != nil {
				return nil, err
			}
			client, err := mcpMailClientOf(call)
			if err != nil {
				return nil, err
			}
			return mcpMailRead(ctx, call, client, month, messageId, &repoId, errMcpResourceNotFound(), result)
		},
		Subscribe: func(ctx context.Context, session *McpSession, uri string, variables map[string]string) error {
			_, _, _, err := mcpMailMessageVariables(variables)
			return err
		},
	})
}
