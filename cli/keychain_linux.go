//go:build linux && !android

// The Linux stores (§5.9): on a desktop, U's wrap in the Secret Service over the session D-Bus, one item a name in the
// default collection, labelled for ur and found by its attributes; on a headless host, the pass, else a 0600 key file
// with a warning in `ur status`. A host with no session bus or no Secret Service is headless. Once the Secret Service
// is chosen, a daemon that stops answering, or a locked collection, is Failed or Locked, never Absent (D-CORE-15).
//
// Secrets cross the bus in the "plain" session algorithm, which the specification allows between a client and the
// service on one host; the dh-ietf1024-sha256-aes128-cbc-pkcs7 session is not built yet.

package main

import (
	"errors"
	"os"

	"github.com/godbus/dbus/v5"

	"github.com/urnetwork/sidecar"
)

// The Secret Service's names (freedesktop.org Secret Service API 0.2).
const (
	secretServiceName         = "org.freedesktop.secrets"
	secretServicePath         = "/org/freedesktop/secrets"
	secretServiceInterface    = "org.freedesktop.Secret.Service"
	secretCollectionInterface = "org.freedesktop.Secret.Collection"
	secretItemInterface       = "org.freedesktop.Secret.Item"
	secretSessionInterface    = "org.freedesktop.Secret.Session"
	// The attribute that marks this tool's items, and the one naming each.
	secretServiceApplication = "network.ur.cli"
	// "/" is the specification's no object, as a prompt or a missing alias answers.
	secretServiceNoObject = dbus.ObjectPath("/")
)

// A Secret Service Secret struct, (oayays).
type secretServiceSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// The Secret Service over one session bus connection.
type dbusSecretService struct {
	conn *dbus.Conn
}

// The service's object.
func (self *dbusSecretService) service() dbus.BusObject {
	return self.conn.Object(secretServiceName, secretServicePath)
}

// The attributes that find one item.
func secretServiceAttributes(name string) map[string]string {
	return map[string]string{"application": secretServiceApplication, "name": name}
}

// A plain session, which the caller closes.
func (self *dbusSecretService) openSession() (dbus.ObjectPath, error) {
	var output dbus.Variant
	var session dbus.ObjectPath
	if err := self.service().Call(secretServiceInterface+".OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&output, &session); err != nil {
		return "", err
	}
	return session, nil
}

// Closes a session.
func (self *dbusSecretService) closeSession(session dbus.ObjectPath) {
	self.conn.Object(secretServiceName, session).Call(secretSessionInterface+".Close", 0)
}

// The unlocked and locked items holding name.
func (self *dbusSecretService) search(name string) ([]dbus.ObjectPath, []dbus.ObjectPath, error) {
	var unlocked, locked []dbus.ObjectPath
	if err := self.service().Call(secretServiceInterface+".SearchItems", 0, secretServiceAttributes(name)).Store(&unlocked, &locked); err != nil {
		return nil, nil, err
	}
	return unlocked, locked, nil
}

// The item's secret. See secretServiceCalls.
func (self *dbusSecretService) get(name string) ([]byte, bool, bool, error) {
	unlocked, locked, err := self.search(name)
	if err != nil {
		return nil, false, false, err
	}
	if len(unlocked) == 0 {
		return nil, false, 0 < len(locked), nil
	}
	session, err := self.openSession()
	if err != nil {
		return nil, false, false, err
	}
	defer self.closeSession(session)
	secrets := map[dbus.ObjectPath]secretServiceSecret{}
	if err := self.service().Call(secretServiceInterface+".GetSecrets", 0, unlocked[:1], session).Store(&secrets); err != nil {
		return nil, false, false, err
	}
	secret, ok := secrets[unlocked[0]]
	if !ok {
		return nil, false, false, errors.New("the secret service answered no secret for its item")
	}
	return secret.Value, true, false, nil
}

// The default collection, and whether it is locked.
func (self *dbusSecretService) defaultCollection() (dbus.BusObject, bool, error) {
	var path dbus.ObjectPath
	if err := self.service().Call(secretServiceInterface+".ReadAlias", 0, "default").Store(&path); err != nil {
		return nil, false, err
	}
	if path == secretServiceNoObject || path == "" {
		return nil, false, errors.New("the secret service has no default collection")
	}
	collection := self.conn.Object(secretServiceName, path)
	lockedVariant, err := collection.GetProperty(secretCollectionInterface + ".Locked")
	if err != nil {
		return nil, false, err
	}
	locked, ok := lockedVariant.Value().(bool)
	if !ok {
		return nil, false, errors.New("the collection's Locked is not a bool")
	}
	return collection, locked, nil
}

// Creates or replaces the item. See secretServiceCalls.
func (self *dbusSecretService) put(name string, value []byte) (bool, error) {
	collection, locked, err := self.defaultCollection()
	if err != nil || locked {
		return locked, err
	}
	session, err := self.openSession()
	if err != nil {
		return false, err
	}
	defer self.closeSession(session)
	properties := map[string]dbus.Variant{
		secretItemInterface + ".Label":      dbus.MakeVariant("ur unlock key"),
		secretItemInterface + ".Attributes": dbus.MakeVariant(secretServiceAttributes(name)),
	}
	secret := secretServiceSecret{Session: session, Parameters: []byte{}, Value: value, ContentType: "application/octet-stream"}
	var item, prompt dbus.ObjectPath
	if err := collection.Call(secretCollectionInterface+".CreateItem", 0, properties, secret, true).Store(&item, &prompt); err != nil {
		return false, err
	}
	// a prompt is a person's to answer, which a daemon cannot: the collection reads as locked
	return prompt != secretServiceNoObject, nil
}

// Deletes the item. See secretServiceCalls.
func (self *dbusSecretService) remove(name string) (bool, error) {
	unlocked, locked, err := self.search(name)
	if err != nil {
		return false, err
	}
	if 0 < len(locked) {
		return true, nil
	}
	for _, item := range unlocked {
		var prompt dbus.ObjectPath
		if err := self.conn.Object(secretServiceName, item).Call(secretItemInterface+".Delete", 0).Store(&prompt); err != nil {
			return false, err
		}
		if prompt != secretServiceNoObject {
			return true, nil
		}
	}
	return false, nil
}

// A session bus whose Secret Service answers, or an error for a headless host.
func connectSecretService() (*dbusSecretService, error) {
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		return nil, errors.New("no session bus")
	}
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, err
	}
	var owned bool
	if err := conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, secretServiceName).Store(&owned); err != nil {
		conn.Close()
		return nil, err
	}
	if !owned {
		var activatable []string
		if err := conn.BusObject().Call("org.freedesktop.DBus.ListActivatableNames", 0).Store(&activatable); err != nil {
			conn.Close()
			return nil, err
		}
		found := false
		for _, name := range activatable {
			if name == secretServiceName {
				found = true
			}
		}
		if !found {
			conn.Close()
			return nil, errors.New("no secret service on the session bus")
		}
	}
	return &dbusSecretService{conn: conn}, nil
}

// The Secret Service on a desktop; on a headless host the key file, when args allow it, else the pass alone.
func newOsKeyStore(args *osKeyStoreArgs) (sidecar.SidecarKeyStore, osKeyStoreKind, error) {
	service, err := connectSecretService()
	if err == nil {
		return &secretServiceStore{calls: service}, osKeyStoreSecretService, nil
	}
	if args.KeyFileFallback && args.Directory != "" {
		if args.Log != nil {
			args.Log.Warningf("[keychain]no secret service: the unlock key's wrap is in a 0600 key file")
		}
		return &keyFileStore{files: &osKeyStoreDirectory{directory: args.Directory}}, osKeyStoreKeyFile, nil
	}
	return nil, osKeyStorePass, nil
}
