// gkm as production runs it, beside the world's (enginenet.go's world runs gkm caching nothing, so a test sees each
// write at once): what a test of a race those caches make swaps in for gkm's origin, before a bootstrap or after one,
// and the evs barrier such a test holds a creation's placement at. A client package's test reaches both here, since it
// imports no engine package (§4.4's layering).

package enginenet

import (
	"context"
	"errors"
	"net/http"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/gkmservice"
)

// evs's barrier before a creation's place/ If-None-Match, keyed by the repo (evsservice.BarrierPlacePutBefore).
const EvsPlacePutBeforeBarrier = evsservice.BarrierPlacePutBefore

// Serves gkm's origin from a new gkm engine on the Net's host behind the world's gate, at gkmservice's default
// settings, its caches as production runs them: place/'s 404 kept 5 s for reads, repo/, the forms and group-info 5 s, a
// keying repo/ not at all. wrap, nil for none, takes the engine's handler and gives the one served, so a test sees each
// request around the engine's answer. Once a world: the engine is the Net's, closed with it, and the world's own gkm
// stays up serving nothing.
func (self *Engines) ServeProductionGkm(wrap func(engine http.Handler) http.Handler) error {
	revocationSettings := sidecar.DefaultRevocationSettings()
	revocationSettings.Clock = self.net.Clock()
	revocations := sidecar.NewRevocationChecker(self.net.Host().Blobs, func(object []byte) ([]byte, error) {
		return nil, errors.New("this world signs no revocation object")
	}, revocationSettings)
	state := gkmservice.NewAclGkmAuthState(self.cache, revocations, self.net.Clock())
	built, err := self.net.AddEngine("gkm-production", func(ctx context.Context, host *sidecar.ServiceHost) (sidecar.Engine, error) {
		return gkmservice.NewGkmEngine(ctx, host, gkmservice.DefaultGkmServiceSettings(), &gkmservice.GkmEngineDeps{AuthState: state})
	})
	if err != nil {
		return err
	}
	var handler http.Handler = built.(*gkmservice.GkmEngine).Handler()
	if wrap != nil {
		handler = wrap(handler)
	}
	self.api.ServeService(gkmservice.GkmAudience, handler)
	return nil
}
