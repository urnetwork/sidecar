// An sdk host's token source (§5.4's SidecarHost.TokenSource, §5.6's sdk host row, §18.7; CORE-M8-01): the host's Api
// session holds the child's token and refreshes it on its own schedule, with a DPoP proof the core's ClientKey signs,
// so D-CORE-8's refresher stands down. The trap is the order: a strict_exp refresh with no signer is not sent at all
// (§7.4), so the core hands its signer over first, through the optional SidecarTokenSourceSigner, and stands its own
// refresher down only once the source took it. A source that takes no signer leaves the core's refresher on, which
// refreshes with its own proof. The ClientKey seed never leaves the root: the host gets a signing function.
//
// Each new token the source reports is checked to be this generation's client, re-sealed in the keychain, then
// installed in SidecarApi and connect's holders (Store()'s re-seal, §18.7). A host's logout, a confirmed rejection it
// found current (sdk's IsAuthLogoutCurrent), ends this generation through the optional SidecarTokenSourceLogout:
// session_revoked as session_ended, any other as parent_lost, a child's (plan-CORE-parent-lost-signal), and one
// naming an older generation's token is dropped (D-SDK-14). Identity, keys and admission stay; only a verified
// SidecarRevoke means Revoked.
//
// On every leg: root Id, no connect type.

package sidecar

import (
	"context"
	"crypto/rand"
	"errors"
)

// The DPoP signer a token source refreshes with: §7.4's proof over (method, url, ath) by the ClientKey.
type SidecarDpopSigner func(method string, url string, ath string) (string, error)

// A token source that takes the core's DPoP signer: sdk's Api.SetDpopSigner. Optional beside SidecarTokenSource, and
// what stands D-CORE-8's refresher down.
type SidecarTokenSourceSigner interface {
	// Installs signer for the source's refreshes, replacing any. An error leaves the core refreshing.
	SetDpopSigner(signer SidecarDpopSigner) error
}

// A token source that reports its host's logouts. Optional beside SidecarTokenSource.
type SidecarTokenSourceLogout interface {
	// Calls callback with each confirmed rejection of a token the source held, once its host found it current, with
	// the rejection's cause, session_revoked or empty. Returns the removal.
	AddLogoutCallback(callback func(byJwt string, cause string)) func()
}

// A confirmed rejection's cause that ends a session (D-SDK-14).
const sidecarLogoutCauseSessionRevoked = "session_revoked"

// The host's token source, nil for none.
func (self *Sidecar) hostTokenSource() SidecarTokenSource {
	if self.host == nil {
		return nil
	}
	return self.host.TokenSource()
}

// Hands this generation's signer to the host's source, reporting whether the source took it, which stands the core's
// refresher down. False with no source, or one that takes no signer or refuses this one.
func (self *Sidecar) handOffDpopSigner(source SidecarTokenSource, signer SidecarDpopSigner) bool {
	if source == nil || signer == nil {
		return false
	}
	signed, ok := source.(SidecarTokenSourceSigner)
	if !ok {
		self.log.Warningf("[token]the host's token source takes no signer: the core refreshes")
		return false
	}
	if err := signed.SetDpopSigner(signer); err != nil {
		self.log.Warningf("[token]the host's token source refused the signer: the core refreshes: %s", err)
		return false
	}
	return true
}

// Follows the host's source for generation until ctx ends: its new tokens, re-sealed and installed, and its logouts.
// identity is the generation's; persist re-seals a token and install puts it in connect's holders.
func (self *Sidecar) followTokenSource(ctx context.Context, source SidecarTokenSource, generation int64, identity *SidecarIdentity,
	persist func(byJwt string) error, install func(byJwt string), end func(reason SidecarStateReason)) {
	adopt := func(byJwt string) {
		if byJwt == "" || ctx.Err() != nil {
			return
		}
		networkId, clientId, ok := sidecarJwtClient(byJwt)
		if !ok || networkId != identity.NetworkId || clientId != identity.ClientId {
			// another client's token, or another generation's: nothing of it is kept
			self.log.Warningf("[token]the host's token is not generation %d's client", generation)
			return
		}
		if byJwt == self.sidecarApi.currentByJwt() {
			return
		}
		testHookSecret("by_jwt", []byte(byJwt))
		if err := persist(byJwt); err != nil {
			self.log.Warningf("[token]a host token was not re-sealed, and is not installed: %s", err)
			return
		}
		self.sidecarApi.SetByJwt(byJwt)
		if install != nil {
			install(byJwt)
		}
	}
	removeToken := source.AddByJwtCallback(adopt)
	removeLogout := func() {}
	if logouts, ok := source.(SidecarTokenSourceLogout); ok {
		removeLogout = logouts.AddLogoutCallback(func(byJwt string, cause string) {
			_, clientId, ok := sidecarJwtClient(byJwt)
			if !ok || clientId != identity.ClientId {
				// an older generation's logout, dropped (D-SDK-14)
				return
			}
			if cause == sidecarLogoutCauseSessionRevoked {
				end(SidecarReasonSessionEnded)
			} else {
				end(SidecarReasonParentLost)
			}
		})
	}
	if byJwt, err := source.ByJwt(); err == nil {
		adopt(byJwt)
	} else if !errors.Is(err, context.Canceled) && self.log.V(1).Enabled() {
		self.log.Infof("[token]the host's token source holds no token yet: %s", err)
	}
	go func() {
		<-ctx.Done()
		removeToken()
		removeLogout()
	}()
}

// The DPoP signer of this sidecar's current ClientKey (§7.4), for a host to install where it refreshes or mints with
// the child's token (sdk's Api.SetDpopSigner). The seed never leaves the root: this is a signing function.
// ErrSidecarNoIdentity before enrollment, and the keychain's errors while it is locked or failed.
func (self *Sidecar) DpopSigner() (SidecarDpopSigner, error) {
	secrets := self.currentCoreSecrets()
	if secrets == nil {
		return nil, ErrSidecarNoIdentity
	}
	record, err := loadSidecarIdentity(secrets)
	if err != nil {
		return nil, err
	}
	defer record.keys.erase()
	seed := record.keys.clientKeySeedCopy()
	defer clear(seed)
	signer, err := newDpopSigner(seed, self.clock.Now, rand.Reader)
	if err != nil {
		return nil, err
	}
	return signer, nil
}
