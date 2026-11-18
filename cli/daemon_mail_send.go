// The daemon's send methods for a remote-mode app's SidecarMail (QD-853, owner decision 288; §5.8, §18.5): the root's
// mail.check_send, mail.send_result and mail.send (mail_send_daemon.go), registered here beside ur mail's and ur id's
// methods over a target that hosts Sidecars, each acting on its call's network. None is a Confirm method: the first two
// read, and mail.send passes the daemon's gate, which holds a send naming an outside recipient for an I-8 approval. No
// ur command sends them yet, and ur native-host relays none of them.

package main

import (
	"github.com/urnetwork/sidecar"
)

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urMailSendMethods)
}

// The root's send methods on the composition's backends, over a target that hosts Sidecars.
func urMailSendMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	if _, ok := target.(*urDaemonNetwork); !ok {
		return nil
	}
	return sidecar.DaemonMailSendMethods(nil)
}
