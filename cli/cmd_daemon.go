// ur daemon (§5.8, D-CORE-9): one per instance, holding <state>/lock, serving the instance's socket or pipe to
// callers of its own uid. It wires SidecarInstance on the OS backend and newOsKeyStore's wrap of U, the Daemon, and
// one Sidecar, of the network sidecar.json records (a second waits for CORE-M6-01), unlocked by the key store's wrap
// at start when it can be. Its control methods are the person's commands; the mcp and git modes are §16's and §11's
// to register. Its logs go to stderr, never stdout.
//
// --auto-spawned is the relay's: such a daemon exits when idle. --unit is its unit's (install-daemon), and never
// idles out; neither does a daemon a person runs by hand. --ephemeral keeps everything in memory, for an ephemeral
// enrollment (§5.6). Service urls come from §18.9's host table, the one copy of those names (QD-119), and every dial
// goes through HTTPS_PROXY when it names a proxy (https_proxy.go); a table or a proxy ur cannot use runs no Sidecar,
// and status says why. --port and --listen arrive with the local services they place (§11, §15;
// plan-CORE-cli-ui-missing #6).

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
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
		usage:   "  ur daemon [--auto-spawned | --unit] [--ephemeral]",
		summary: "run the instance's daemon in the foreground",
		run:     runUrDaemon,
	})
}

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

// An enrollment's request: the auth key it spends, once.
type urEnrollParams struct {
	AuthKey        string `json:"auth_key"`
	Ephemeral      bool   `json:"ephemeral,omitempty"`
	Replace        bool   `json:"replace,omitempty"`
	DeclaresEgress bool   `json:"declares_egress,omitempty"`
}

// An enrollment's reply.
type urEnrollReply struct {
	Generation int64 `json:"generation"`
}

// What the control methods act on: the instance and, once service urls exist, its Sidecar. A test stands a fake in.
type urDaemonTarget interface {
	// The Sidecar's status, or why none runs.
	status() (sidecar.SidecarStatus, string)
	stats() sidecar.SidecarStats
	unlock(pass []byte) error
	lock()
	enroll(ctx context.Context, credential *sidecar.SidecarEnrollCredential) (int64, error)
	logout(ctx context.Context) error
	changePass(oldPass []byte, newPass []byte) error
	rotateKeychain(ctx context.Context, pass []byte) error
}

// The daemon's instance and Sidecar.
type urDaemonNetwork struct {
	instance  *sidecar.SidecarInstance
	sidecar   *sidecar.Sidecar
	noSidecar string
}

func (self *urDaemonNetwork) status() (sidecar.SidecarStatus, string) {
	if self.sidecar == nil {
		return sidecar.SidecarStatus{}, self.noSidecar
	}
	return self.sidecar.Status(), ""
}

func (self *urDaemonNetwork) stats() sidecar.SidecarStats {
	if self.sidecar == nil {
		return sidecar.SidecarStats{}
	}
	return self.sidecar.Stats()
}

func (self *urDaemonNetwork) unlock(pass []byte) error {
	if self.sidecar != nil {
		return self.sidecar.Unlock(pass)
	}
	return self.instance.Unlock(pass)
}

func (self *urDaemonNetwork) lock() {
	self.instance.Lock()
}

func (self *urDaemonNetwork) enroll(ctx context.Context, credential *sidecar.SidecarEnrollCredential) (int64, error) {
	if self.sidecar == nil {
		credential.Erase()
		return 0, fmt.Errorf("no sidecar runs: %s", self.noSidecar)
	}
	if err := self.sidecar.Enroll(ctx, credential); err != nil {
		return 0, err
	}
	return self.sidecar.Status().Generation, nil
}

func (self *urDaemonNetwork) logout(ctx context.Context) error {
	if self.sidecar == nil {
		return fmt.Errorf("no sidecar runs: %s", self.noSidecar)
	}
	return self.sidecar.Logout(ctx)
}

func (self *urDaemonNetwork) changePass(oldPass []byte, newPass []byte) error {
	return self.instance.ChangePass(oldPass, newPass)
}

func (self *urDaemonNetwork) rotateKeychain(ctx context.Context, pass []byte) error {
	return self.instance.RotateKeychain(ctx, pass)
}

// Registers the control methods on daemon, over target. keyStoreKind is what status names, and hostStores the scan
// it reports.
func registerUrDaemonMethods(daemon *sidecar.Daemon, instance string, target urDaemonTarget, keyStoreKind osKeyStoreKind,
	hostStores func() []sidecar.SidecarHostCredentialStore) error {
	methods := []*sidecar.DaemonMethod{
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
				generation, err := target.enroll(ctx, credential)
				if err != nil {
					return nil, err
				}
				return &urEnrollReply{Generation: generation}, nil
			},
		},
		{
			Name: urMethodLogout,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				return nil, target.logout(ctx)
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
	for _, method := range methods {
		if err := daemon.RegisterMethod(method); err != nil {
			return err
		}
	}
	return nil
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

	daemon, err := sidecar.NewDaemon(ctx, &sidecar.DaemonSettings{
		Instance:       cli.instance,
		StateDirectory: stateDirectory,
		Local:          settings.LocalSettings,
		AutoSpawned:    autoSpawned,
		Version:        sidecar.Version,
		Log:            log,
	})
	if err != nil {
		if errors.Is(err, sidecar.ErrDaemonRunning) {
			return fmt.Errorf("a daemon already runs for instance %s", cli.instance)
		}
		return err
	}
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

	network := &urDaemonNetwork{instance: instance}
	if urlsErr != nil {
		network.noSidecar = urlsErr.Error()
		log.Warningf("[ur]%s", urlsErr)
	} else {
		var networkId *sidecar.Id
		records := instance.Networks()
		if 0 < len(records) {
			networkId = &records[0].NetworkId
			if 1 < len(records) {
				log.Warningf("[ur]%d networks are recorded, and one daemon runs one until several networks land", len(records))
			}
		}
		running, err := sidecar.NewSidecar(ctx, &urSidecarHost{store: instance.Store(networkId), keyStore: keyStore}, nil, settings)
		if err != nil {
			network.noSidecar = err.Error()
			log.Warningf("[ur]no sidecar runs: %s", err)
		} else {
			network.sidecar = running
			defer func() {
				closeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				running.CloseAndWait(closeCtx)
			}()
			// the key store's wrap of U; a pass-only instance stays Locked until ur unlock
			if err := running.Unlock(nil); err != nil && log.V(1).Enabled() {
				log.Infof("[ur]the keychain stays locked: %s", err)
			}
		}
	}
	if err := registerUrDaemonMethods(daemon, cli.instance, network, keyStoreKind, sidecar.HostCredentialStores); err != nil {
		daemon.Close()
		return err
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
