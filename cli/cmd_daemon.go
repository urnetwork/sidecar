// ur daemon (§5.8, D-CORE-9): one per instance, holding <state>/lock, serving the instance's socket or pipe to
// callers of its own uid. It wires SidecarInstance on the OS backend and newOsKeyStore's wrap of U, the Daemon, and a
// Sidecar per network sidecar.json records, all on the one instance, so one U opens every network (CORE-M6-01), plus
// one unenrolled Sidecar a further network's enrollment takes. Each is unlocked by the key store's wrap at start when
// it can be. Its control methods are the person's commands, a network-scoped one acting on its network argument, else
// .ur's, else the only network (CORE-M3-05); the git mode resolves a session's <net> and hands it to §11's git service,
// and the mcp mode is §16's server (mcp.McpServer), one go-sdk session per relay connection, which only this binary
// links (D-MCP-1, D-MCP-2). Its logs go to stderr, never stdout.
//
// --auto-spawned is the relay's: such a daemon exits when idle. --unit is its unit's (install-daemon), and never
// idles out; neither does a daemon a person runs by hand. --ephemeral keeps everything in memory, for an ephemeral
// enrollment (§5.6). --port sets the first port of the local services and --listen the addresses they bind, every
// interface otherwise (owner decision 84; plan-CORE-cli-ui-missing #6). Service urls come from §18.9's host table, the
// one copy of those names (QD-119), and every dial goes through HTTPS_PROXY when it names a proxy (https_proxy.go); a
// table or a proxy ur cannot use runs no Sidecar, and status says why.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mcp"
)

// The control methods ur's commands call (§5.8). Each name is a reading: §5.8 names the mode, not the methods.
const (
	urMethodStatus         = "status"
	urMethodUnlock         = "unlock"
	urMethodLock           = "lock"
	urMethodEnroll         = "enroll"
	urMethodLogout         = "logout"
	urMethodKeychainPass   = "keychain.pass"
	urMethodKeychainRotate = "keychain.rotate"
)

// The directory in <state> that holds a key store's files: DPAPI blobs, or a headless host's key file.
const urKeyStoreDirectoryName = "keystore"

func init() {
	registerUrCommand(&urCommand{
		name:    "daemon",
		usage:   "  ur daemon [--auto-spawned | --unit] [--ephemeral] [--port=<port>] [--listen=<ip>...]",
		summary: "run the instance's daemon in the foreground",
		run:     runUrDaemon,
	})
}

// §11's git service, which EVS1-M2-38 assigns (EvsClient.ServeGit): nil until then, and the git mode refuses every
// session with git's ERR line.
var urDaemonGitService sidecar.DaemonGitService

// status's params.
type urStatusParams struct {
	Stats bool `json:"stats,omitempty"`
}

// status's reply: nothing secret, which the daemon's reply walk holds it to.
type urStatusReply struct {
	Instance   string `json:"instance"`
	State      string `json:"state,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Generation int64  `json:"generation,omitempty"`
	// Why no Sidecar runs, when none does.
	NoSidecar string `json:"no_sidecar,omitempty"`
	// Which store wraps U: keychain, dpapi, secret_service, key_file or pass.
	KeyStore string `json:"key_store"`
	// app, extension: stores on this host holding a network credential (D-TRUST-3), by kind alone.
	CredentialStores []string              `json:"credential_stores,omitempty"`
	Stats            *sidecar.SidecarStats `json:"stats,omitempty"`
	// Each network the daemon hosts, a failed one among them (CORE-M6-01).
	Networks []urNetworkStatus `json:"networks,omitempty"`
	// The local services' listeners, those the LAN reaches marked (§22.5).
	LocalListeners []sidecar.DaemonLocalListenerStatus `json:"local_listeners,omitempty"`
	// The sockets and live shares the daemon holds, each keeping it up (§5.8, §9.9).
	Sockets    int `json:"sockets,omitempty"`
	LiveShares int `json:"live_shares,omitempty"`
}

// One hosted network in status: ids and its state, nothing secret.
type urNetworkStatus struct {
	NetworkId  sidecar.Id  `json:"network_id"`
	SidecarId  *sidecar.Id `json:"sidecar_id,omitempty"`
	State      string      `json:"state"`
	Reason     string      `json:"reason,omitempty"`
	Generation int64       `json:"generation,omitempty"`
}

// A pass, from the terminal, in a request: a request may carry one, a reply never does.
type urPassParams struct {
	Pass []byte `json:"pass"`
}

// A pass change.
type urPassChangeParams struct {
	OldPass []byte `json:"old_pass"`
	NewPass []byte `json:"new_pass"`
}

// An enrollment's request: the auth key it spends, once, and the hosted network it re-enrolls, empty for whichever the
// daemon picks (urDaemonNetwork.enroll).
type urEnrollParams struct {
	AuthKey        string `json:"auth_key"`
	Ephemeral      bool   `json:"ephemeral,omitempty"`
	Replace        bool   `json:"replace,omitempty"`
	DeclaresEgress bool   `json:"declares_egress,omitempty"`
	Network        string `json:"network,omitempty"`
}

// A network-scoped call's params: the network argument, empty for .ur's or the only one (§5.8).
type urNetworkParams struct {
	Network string `json:"network,omitempty"`
}

// An enrollment's reply.
type urEnrollReply struct {
	Generation int64 `json:"generation"`
}

// What the control methods act on: the instance and, once service urls exist, its Sidecars. A test stands a fake in.
type urDaemonTarget interface {
	// The first hosted network's status, or why none runs.
	status() (sidecar.SidecarStatus, string)
	stats() sidecar.SidecarStats
	unlock(pass []byte) error
	lock()
	// Enrolls into network, a hosted one by name, or, empty, the one urDaemonNetwork.enroll picks.
	enroll(ctx context.Context, credential *sidecar.SidecarEnrollCredential, network string) (int64, error)
	// Logs the hosted network networkId out, leaving the others running.
	logout(ctx context.Context, networkId sidecar.Id) error
	changePass(oldPass []byte, newPass []byte) error
	rotateKeychain(ctx context.Context, pass []byte) error
}

// A target that hosts several networks and local listeners, for status's lists.
type urNetworksTarget interface {
	networkStatuses() []urNetworkStatus
	localListeners() []sidecar.DaemonLocalListenerStatus
}

// The daemon's instance and its Sidecars, one per network (CORE-M6-01), and the unenrolled one a further network's
// enrollment takes, which joins the daemon's registry once it has a network. Safe for concurrent use.
type urDaemonNetwork struct {
	instance  *sidecar.SidecarInstance
	daemon    *sidecar.Daemon
	noSidecar string
	// a running Sidecar on the instance's store of networkId, nil for one not enrolled yet
	start func(networkId *sidecar.Id) (*sidecar.Sidecar, error)
	// ends a Sidecar the daemon no longer hosts
	stop func(running *sidecar.Sidecar)
	// the networks' bridges and the instance's ur tun (bridge_wire.go), nil for a target with none
	bridges *urBridgeDaemon

	// one enrollment at a time, since the further network's Sidecar joins the registry when it lands
	enrollLock sync.Mutex

	stateLock sync.Mutex
	further   *sidecar.Sidecar
}

// The hosted Sidecars, in network order.
func (self *urDaemonNetwork) hosted() []sidecar.DaemonNetwork {
	if self.daemon == nil {
		return nil
	}
	return self.daemon.Sidecars()
}

// The Sidecar a further network's enrollment takes, started when there is none.
func (self *urDaemonNetwork) furtherSidecar() (*sidecar.Sidecar, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.further != nil {
		return self.further, nil
	}
	if self.start == nil {
		return nil, fmt.Errorf("no sidecar runs: %s", self.noSidecar)
	}
	further, err := self.start(nil)
	if err != nil {
		return nil, err
	}
	self.further = further
	return further, nil
}

func (self *urDaemonNetwork) status() (sidecar.SidecarStatus, string) {
	if hosted := self.hosted(); 0 < len(hosted) {
		return hosted[0].Sidecar.Status(), ""
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.further != nil {
		return self.further.Status(), ""
	}
	return sidecar.SidecarStatus{}, self.noSidecar
}

func (self *urDaemonNetwork) networkStatuses() []urNetworkStatus {
	statuses := []urNetworkStatus{}
	for _, network := range self.hosted() {
		status := network.Sidecar.Status()
		networkStatus := urNetworkStatus{
			NetworkId:  network.NetworkId,
			State:      string(status.State),
			Reason:     string(status.Reason),
			Generation: status.Generation,
		}
		if identity := network.Sidecar.Identity(); identity != nil {
			networkStatus.SidecarId = &identity.SidecarId
		}
		statuses = append(statuses, networkStatus)
	}
	return statuses
}

func (self *urDaemonNetwork) localListeners() []sidecar.DaemonLocalListenerStatus {
	if self.daemon == nil {
		return nil
	}
	return self.daemon.LocalListeners()
}

func (self *urDaemonNetwork) stats() sidecar.SidecarStats {
	if hosted := self.hosted(); 0 < len(hosted) {
		return hosted[0].Sidecar.Stats()
	}
	return sidecar.SidecarStats{}
}

// U opens every network's keychain at once (§5.9): the instance's unlock, then each Sidecar looks again.
func (self *urDaemonNetwork) unlock(pass []byte) error {
	if err := self.instance.Unlock(pass); err != nil {
		return err
	}
	for _, network := range self.hosted() {
		network.Sidecar.Unlock(nil)
	}
	return nil
}

func (self *urDaemonNetwork) lock() {
	self.instance.Lock()
}

// Enrolls credential: into the hosted network named, re-enrolling it; else, with no network named, into the only
// hosted network when it waits to re-enroll, and otherwise as a further network through the unenrolled Sidecar, which
// then joins the registry under the network its enrollment names. A further enrollment whose key is for a network
// the instance holds is refused (Sidecar.Enroll), naming the way to re-enroll that one.
func (self *urDaemonNetwork) enroll(ctx context.Context, credential *sidecar.SidecarEnrollCredential, network string) (int64, error) {
	self.enrollLock.Lock()
	defer self.enrollLock.Unlock()
	hosted := self.hosted()
	var target *sidecar.Sidecar
	switch {
	case network != "":
		networkId, err := self.daemon.ResolveNetwork(&sidecar.DaemonHello{Mode: sidecar.DaemonModeControl}, network)
		if err != nil {
			credential.Erase()
			return 0, err
		}
		target, _ = self.daemon.SidecarForNetwork(networkId)
	case len(hosted) == 1 && (hosted[0].Sidecar.Status().State == sidecar.SidecarStateUnenrolled || hosted[0].Sidecar.Paired()):
		// a paired sidecar's ur login unpairs it (§5.8's unpair row)
		target = hosted[0].Sidecar
	}
	further := target == nil
	if further {
		var err error
		target, err = self.furtherSidecar()
		if err != nil {
			credential.Erase()
			return 0, err
		}
	}
	if err := target.Enroll(ctx, credential); err != nil {
		return 0, err
	}
	if further {
		networkId := target.NetworkId()
		if networkId == nil {
			return 0, errors.New("the enrollment named no network")
		}
		if err := self.daemon.AddSidecar(*networkId, target); err != nil {
			return 0, err
		}
		self.stateLock.Lock()
		self.further = nil
		self.stateLock.Unlock()
	}
	return target.Status().Generation, nil
}

// §5.8's pair (CORE-M8-02): the child's token goes to the hosted Sidecar of its network, else the unenrolled one, which
// then joins the registry under that network, as an enrollment's does. The reply names no token.
func (self *urDaemonNetwork) PairChild(ctx context.Context, childJwt string) (*sidecar.DaemonPairReply, error) {
	self.enrollLock.Lock()
	defer self.enrollLock.Unlock()
	if self.daemon == nil {
		return nil, fmt.Errorf("no sidecar runs: %s", self.noSidecar)
	}
	networkId, ok := sidecar.DaemonPairNetwork(childJwt)
	if !ok {
		return nil, sidecar.ErrSidecarPairToken
	}
	target, hosted := self.daemon.SidecarForNetwork(networkId)
	if !hosted {
		var err error
		target, err = self.furtherSidecar()
		if err != nil {
			return nil, err
		}
	}
	if err := target.Pair(ctx, childJwt); err != nil {
		return nil, err
	}
	if !hosted {
		if err := self.daemon.AddSidecar(networkId, target); err != nil {
			return nil, err
		}
		self.stateLock.Lock()
		self.further = nil
		self.stateLock.Unlock()
	}
	return &sidecar.DaemonPairReply{NetworkId: networkId, Generation: target.BoundGeneration()}, nil
}

// Logs networkId out (CORE-M2-07) and stops hosting it; the other networks run on.
func (self *urDaemonNetwork) logout(ctx context.Context, networkId sidecar.Id) error {
	running, ok := self.daemon.SidecarForNetwork(networkId)
	if !ok {
		return fmt.Errorf("no sidecar runs for network %s", networkId)
	}
	if err := running.Logout(ctx); err != nil {
		return err
	}
	if removed := self.daemon.RemoveSidecar(networkId); removed != nil && self.stop != nil {
		self.stop(removed)
	}
	if len(self.hosted()) == 0 {
		// the next ur login has an unenrolled Sidecar to take, and status a state to show
		if _, err := self.furtherSidecar(); err != nil {
			return fmt.Errorf("logged out, and no sidecar runs: %w", err)
		}
	}
	return nil
}

func (self *urDaemonNetwork) changePass(oldPass []byte, newPass []byte) error {
	return self.instance.ChangePass(oldPass, newPass)
}

func (self *urDaemonNetwork) rotateKeychain(ctx context.Context, pass []byte) error {
	return self.instance.RotateKeychain(ctx, pass)
}

// The only hosted network's Sidecar, for a method that does not name one yet: ur approve's. Several answer
// FAILED_PRECONDITION's error naming them (CORE-M3-05).
func (self *urDaemonNetwork) onlySidecar() (*sidecar.Sidecar, error) {
	if self.daemon == nil {
		return nil, fmt.Errorf("no sidecar runs: %s", self.noSidecar)
	}
	networkId, err := self.daemon.ResolveNetwork(&sidecar.DaemonHello{Mode: sidecar.DaemonModeControl}, "")
	if err != nil {
		return nil, err
	}
	running, ok := self.daemon.SidecarForNetwork(networkId)
	if !ok {
		return nil, fmt.Errorf("no sidecar runs: %s", self.noSidecar)
	}
	return running, nil
}

// Registers the control methods on daemon, over target. keyStoreKind is what status names, and hostStores the scan
// it reports.
func registerUrDaemonMethods(daemon *sidecar.Daemon, instance string, target urDaemonTarget, keyStoreKind osKeyStoreKind,
	hostStores func() []sidecar.SidecarHostCredentialStore) error {
	for _, method := range urDaemonMethods(instance, target, keyStoreKind, hostStores) {
		if err := daemon.RegisterMethod(method); err != nil {
			return err
		}
	}
	return nil
}

// Control methods another command's file adds over the same target, at init, so each command keeps to its own
// cmd_<name>.go (C-21): ur approve's, among them, and pair's below.
var urDaemonMethodExtensions = []func(target urDaemonTarget) []*sidecar.DaemonMethod{urPairMethods}

// pair (§5.8, CORE-M8-02) over a target that hosts Sidecars.
func urPairMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	pairs, ok := target.(sidecar.DaemonPairTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{sidecar.DaemonPairMethod(pairs)}
}

// The control methods ur's daemon serves, over target: what registerUrDaemonMethods registers, and what a test reads
// to hold ur native-host to every Confirm method among them.
func urDaemonMethods(instance string, target urDaemonTarget, keyStoreKind osKeyStoreKind,
	hostStores func() []sidecar.SidecarHostCredentialStore) []*sidecar.DaemonMethod {
	methods := urDaemonCoreMethods(instance, target, keyStoreKind, hostStores)
	for _, extension := range urDaemonMethodExtensions {
		methods = append(methods, extension(target)...)
	}
	return methods
}

// The control methods of this file's own commands.
func urDaemonCoreMethods(instance string, target urDaemonTarget, keyStoreKind osKeyStoreKind,
	hostStores func() []sidecar.SidecarHostCredentialStore) []*sidecar.DaemonMethod {
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodStatus,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urStatusParams{}
				decodeUrParams(call, params)
				status, noSidecar := target.status()
				reply := &urStatusReply{
					Instance:   instance,
					State:      string(status.State),
					Reason:     string(status.Reason),
					Generation: status.Generation,
					NoSidecar:  noSidecar,
					KeyStore:   string(keyStoreKind),
				}
				for _, store := range hostStores() {
					reply.CredentialStores = append(reply.CredentialStores, store.Kind)
				}
				if networks, ok := target.(urNetworksTarget); ok {
					reply.Networks = networks.networkStatuses()
					reply.LocalListeners = networks.localListeners()
				}
				if sockets, ok := target.(urSocketsTarget); ok {
					reply.Sockets, reply.LiveShares = sockets.socketCounts()
				}
				if params.Stats {
					stats := target.stats()
					reply.Stats = &stats
				}
				return reply, nil
			},
		},
		{
			Name: urMethodUnlock,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urPassParams{}
				if err := decodeUrParams(call, params); err != nil || len(params.Pass) == 0 {
					return nil, errors.New("unlock takes a pass")
				}
				defer clear(params.Pass)
				return nil, target.unlock(params.Pass)
			},
		},
		{
			Name: urMethodLock,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				target.lock()
				return nil, nil
			},
		},
		{
			Name: urMethodEnroll,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urEnrollParams{}
				if err := decodeUrParams(call, params); err != nil || params.AuthKey == "" {
					return nil, errors.New("enroll takes an auth key")
				}
				credential := &sidecar.SidecarEnrollCredential{
					AuthKey:        params.AuthKey,
					Ephemeral:      params.Ephemeral,
					Replace:        params.Replace,
					DeclaresEgress: params.DeclaresEgress,
				}
				params.AuthKey = ""
				generation, err := target.enroll(ctx, credential, params.Network)
				if err != nil {
					return nil, err
				}
				return &urEnrollReply{Generation: generation}, nil
			},
		},
		{
			Name:    urMethodLogout,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				return nil, target.logout(ctx, call.NetworkId)
			},
		},
		{
			Name: urMethodKeychainPass,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urPassChangeParams{}
				if err := decodeUrParams(call, params); err != nil || len(params.NewPass) == 0 {
					return nil, errors.New("a pass change takes the new pass")
				}
				defer clear(params.OldPass)
				defer clear(params.NewPass)
				return nil, target.changePass(params.OldPass, params.NewPass)
			},
		},
		{
			Name: urMethodKeychainRotate,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urPassParams{}
				decodeUrParams(call, params)
				defer clear(params.Pass)
				return nil, target.rotateKeychain(ctx, params.Pass)
			},
		},
	}
}

// Decodes a call's params into params. No params is an empty object.
func decodeUrParams(call *sidecar.DaemonCall, params any) error {
	if len(call.Params) == 0 {
		return nil
	}
	return jsonUnmarshalStrict(call.Params, params)
}

// A host of one Sidecar: the instance's store for its network, and the key store's wrap of U.
type urSidecarHost struct {
	store    sidecar.SidecarStore
	keyStore sidecar.SidecarKeyStore
}

func (self *urSidecarHost) Store() sidecar.SidecarStore {
	return self.store
}

func (self *urSidecarHost) KeyStore() sidecar.SidecarKeyStore {
	return self.keyStore
}

func (self *urSidecarHost) TokenSource() sidecar.SidecarTokenSource {
	return nil
}

// Fills settings' service urls from §18.9's embedded host table, the one copy of those names (QD-119). A table that
// does not parse or misses a service fills nothing, and validate refuses the empty urls on every leg.
func urServiceUrlsFromHostTable(settings *sidecar.SidecarSettings) error {
	list, err := sidecar.SidecarHostListV1()
	if err != nil {
		return fmt.Errorf("no service urls: %w", err)
	}
	return list.ApplyServiceUrls(settings)
}

// Runs the daemon until ctx ends, Close, or an auto-spawned daemon's idle exit.
func runUrDaemon(ctx context.Context, cli *urCli, options docopt.Opts) error {
	autoSpawned, _ := options.Bool("--auto-spawned")
	ephemeral, _ := options.Bool("--ephemeral")
	log := newUrStderrLogger(cli.stderr)

	stateDirectory, err := sidecar.SidecarStateDirectory(cli.instance)
	if err != nil {
		return err
	}
	settings := sidecar.DefaultSidecarSettings()
	settings.Instance = cli.instance
	settings.Log = log
	urlsErr := cli.serviceUrls(settings)
	if urlsErr == nil {
		// a proxy ur cannot use runs no Sidecar, rather than a direct one
		urlsErr = applyUrHttpsProxy(cli.getenv, settings)
	}

	var keyStore sidecar.SidecarKeyStore
	keyStoreKind := osKeyStorePass
	var backend sidecar.SidecarStoreBackend
	var machineId []byte
	if ephemeral {
		keyStore = sidecar.NewSidecarMemoryKeyStore()
		keyStoreKind = "memory"
		backend = sidecar.NewSidecarMemoryBackend()
	} else {
		keyStore, keyStoreKind, err = newOsKeyStore(&osKeyStoreArgs{
			Directory:       filepath.Join(stateDirectory, urKeyStoreDirectoryName),
			KeyFileFallback: true,
			Log:             log,
		})
		if err != nil {
			log.Warningf("[ur]no OS key store: the pass alone wraps the unlock key: %s", err)
			keyStore = nil
			keyStoreKind = osKeyStorePass
		}
		backend, err = sidecar.NewSidecarOsBackend(stateDirectory)
		if err != nil {
			return err
		}
		machineId = sidecar.SidecarMachineId()
	}

	if port, _ := options.String("--port"); port != "" {
		firstPort, err := strconv.Atoi(port)
		if err != nil || firstPort < 1 || 65535-3 < firstPort {
			return fmt.Errorf("--port takes a port from 1 to %d", 65535-3)
		}
		settings.LocalSettings.FirstPort = firstPort
	}
	listen, _ := options["--listen"].([]string)

	daemon, err := sidecar.NewDaemon(ctx, &sidecar.DaemonSettings{
		Instance:       cli.instance,
		StateDirectory: stateDirectory,
		Local:          settings.LocalSettings,
		AutoSpawned:    autoSpawned,
		Version:        sidecar.Version,
		Listen:         listen,
		Log:            log,
	})
	if err != nil {
		if errors.Is(err, sidecar.ErrDaemonRunning) {
			return fmt.Errorf("a daemon already runs for instance %s", cli.instance)
		}
		return err
	}
	// §16.6's presence prompt: the host's authenticator, nil where it has none (presence.go)
	daemon.SetPresenceProvider(urPlatformPresenceProvider(stateDirectory, settings.Ingest, log))
	instance, err := sidecar.NewSidecarInstance(ctx, &sidecar.SidecarInstanceArgs{
		Backend:   backend,
		KeyStore:  keyStore,
		MachineId: machineId,
		Settings:  settings,
	})
	if err != nil {
		daemon.Close()
		return err
	}
	defer instance.Close()

	// every Sidecar this daemon starts, closed at its end
	var runningLock sync.Mutex
	runningSidecars := map[*sidecar.Sidecar]bool{}
	closeSidecar := func(running *sidecar.Sidecar) {
		runningLock.Lock()
		delete(runningSidecars, running)
		runningLock.Unlock()
		closeCtx, cancel := context.WithTimeout(context.Background(), cli.settings.CloseTimeout)
		defer cancel()
		running.CloseAndWait(closeCtx)
	}
	defer func() {
		runningLock.Lock()
		remaining := []*sidecar.Sidecar{}
		for running := range runningSidecars {
			remaining = append(remaining, running)
		}
		runningLock.Unlock()
		for _, running := range remaining {
			closeSidecar(running)
		}
	}()
	network := &urDaemonNetwork{instance: instance, daemon: daemon, stop: closeSidecar}
	// the bridges and ur tun end with the daemon, the tun's routes removed, on every path Run returns by
	network.bridges = newUrBridgeDaemon(ctx, urBridgeDaemonArgsOf(cli.instance, log))
	defer network.bridges.close()
	if urlsErr != nil {
		network.noSidecar = urlsErr.Error()
		log.Warningf("[ur]%s", urlsErr)
	} else {
		network.start = func(networkId *sidecar.Id) (*sidecar.Sidecar, error) {
			running, err := sidecar.NewSidecar(ctx, &urSidecarHost{store: instance.Store(networkId), keyStore: keyStore}, nil, settings)
			if err != nil {
				return nil, err
			}
			runningLock.Lock()
			runningSidecars[running] = true
			runningLock.Unlock()
			return running, nil
		}
		// a Sidecar per recorded network, each on the one instance, so the key store's wrap of U opens them all
		for _, record := range instance.Networks() {
			networkId := record.NetworkId
			running, err := network.start(&networkId)
			if err != nil {
				log.Warningf("[ur]network %s runs no sidecar: %s", networkId, err)
				continue
			}
			if err := daemon.AddSidecar(networkId, running); err != nil {
				log.Warningf("[ur]network %s: %s", networkId, err)
				closeSidecar(running)
			}
		}
		if len(daemon.Sidecars()) == 0 {
			if _, err := network.furtherSidecar(); err != nil {
				network.noSidecar = err.Error()
				log.Warningf("[ur]no sidecar runs: %s", err)
			}
		}
		// the key store's wrap of U; a pass-only instance stays Locked until ur unlock
		if err := instance.Unlock(nil); err != nil && log.V(1).Enabled() {
			log.Infof("[ur]the keychain stays locked: %s", err)
		}
	}
	if err := daemon.RegisterMode(sidecar.DaemonModeGit, sidecar.NewDaemonGitMode(daemon, urDaemonGitService)); err != nil {
		daemon.Close()
		return err
	}
	// a mount's git hooks, which ur git-hook relays (git_hook.go)
	if err := daemon.RegisterMode(sidecar.DaemonModeGitHook, urDaemonGitHookMode(daemon)); err != nil {
		daemon.Close()
		return err
	}
	// §16's MCP, whatever the networks' states: a call on a Locked or Unenrolled one names what the person runs
	mcpServer := mcp.NewMcpServer(mcp.DaemonOf(daemon), mcp.NewMcpServerSettings(settings, sidecar.Version))
	if err := daemon.RegisterMode(sidecar.DaemonModeMcp, mcpServer.Serve); err != nil {
		daemon.Close()
		return err
	}
	// §16.7's restore points and ingest: each network's Sidecar.Record writes the entries, and the points hold
	// each PreToolUse's paths
	home, _ := os.UserHomeDir()
	ingest := mcp.NewIngest(&mcp.IngestArgs{
		Server:  mcpServer,
		Restore: mcp.NewRestorePoints(&mcp.RestorePointsArgs{Clock: settings.Clock, Ingest: settings.Ingest, Log: log}),
		Home:    home,
		Record:  settings.Record,
	})
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), cli.settings.CloseTimeout)
		defer cancel()
		ingest.Close(closeCtx)
	}()
	// §16.5's tools, each registered from its owner's file, their W calls recorded as tool_call entries through ingest
	mcp.NewDaemonMcpCatalog(mcpServer, ingest).Install(mcpServer)
	// §16.6's harness evidence: each PermissionRequest the capture sealed, kept for a network's gate to ask about
	// (MCP-M3-10), on the hook path after the ingest's capture
	mcp.NewHarnessEvidenceStore(settings.Ingest, settings.Clock).Install(mcpServer)
	// §16.6's config check over the seals ur install-harness wrote (cmd_install_harness.go): a harness with none, or
	// whose files no longer hold ur's entries, taints its runs
	mcpServer.Binder().SetConfigCheck(mcp.NewHarnessConfigHashes(&mcp.HarnessConfigHashesArgs{
		StateDirectory: stateDirectory,
		Executable:     urHarnessExecutable,
		Ingest:         settings.Ingest,
	}).Check)
	// ur hook's hook.event, which shares the server's run bindings (§16.7)
	for _, method := range mcpServer.DaemonMethods() {
		if err := daemon.RegisterMethod(method); err != nil {
			daemon.Close()
			return err
		}
	}
	if err := registerUrDaemonMethods(daemon, cli.instance, network, keyStoreKind, sidecar.HostCredentialStores); err != nil {
		daemon.Close()
		return err
	}
	// a sandboxed macOS app pairs and calls through its app-group container's socket (§5.9; CORE-M8-02); the paths
	// name the user's home, so only their count is logged
	if listening := daemon.ServeAppGroupSockets(); 0 < len(listening) && log.V(1).Enabled() {
		log.Infof("[ur]listening in %d app-group containers too", len(listening))
	}
	// an interrupt or a terminate ends the run, which Accept alone would not see
	stopOnSignal := context.AfterFunc(ctx, daemon.Close)
	defer stopOnSignal()
	log.Infof("[ur]daemon of instance %s serving", cli.instance)
	err = daemon.Run()
	if err != nil && !errors.Is(err, os.ErrClosed) {
		return err
	}
	return nil
}
