//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// The labels' sealed directory of a fresh, unlocked network on a memory medium.
func testListenersLabelsStore(t *testing.T) SidecarStore {
	t.Helper()
	instance, _, _ := enrolledInstance(t)
	return storeOf(t, instance, testNetworkId, "listeners")
}

// Labels and hides survive a restart of their store: what the person wrote reads back from a new ListenersLabels on
// the same directory, a label cleaned as a description, a cleared label and an unhide gone.
func TestListenersLabelsSurviveARestart(t *testing.T) {
	store := testListenersLabelsStore(t)
	labels, err := OpenListenersLabels(store, DefaultListenersSettings())
	if err != nil {
		t.Fatal(err)
	}
	if labels.HidesDevice() {
		t.Fatal("a fresh store hides the device")
	}
	tcp := protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP
	udp := protocol.ListenersProtocol_LISTENERS_PROTOCOL_UDP
	if err := labels.SetLabel(tcp, 3000, &ListenersLabel{Text: "  the\tshop ", Type: "_http._tcp"}); err != nil {
		t.Fatal(err)
	}
	if err := labels.SetLabel(udp, 51820, &ListenersLabel{Text: "wireguard", Type: ListenersLabelTypeNone}); err != nil {
		t.Fatal(err)
	}
	if err := labels.SetLabel(tcp, 8000, &ListenersLabel{Text: "gone"}); err != nil {
		t.Fatal(err)
	}
	if err := labels.SetLabel(tcp, 8000, nil); err != nil {
		t.Fatal(err)
	}
	for _, port := range []uint16{5432, 445} {
		if err := labels.SetHidden(tcp, port, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := labels.SetHidden(tcp, 445, false); err != nil {
		t.Fatal(err)
	}

	restarted, err := OpenListenersLabels(store, DefaultListenersSettings())
	if err != nil {
		t.Fatal(err)
	}
	if label, ok := restarted.Label(tcp, 3000); !ok || label.Text != "the shop" || label.Type != "_http._tcp" {
		t.Errorf("the shop: %v, %t", label, ok)
	}
	if label, ok := restarted.Label(udp, 51820); !ok || label.Type != ListenersLabelTypeNone {
		t.Errorf("wireguard: %v, %t", label, ok)
	}
	if _, ok := restarted.Label(tcp, 8000); ok {
		t.Error("a cleared label read back")
	}
	if _, ok := restarted.Label(udp, 3000); ok {
		t.Error("a label of another protocol read back")
	}
	if !restarted.HidesPort(tcp, 5432) || restarted.HidesPort(tcp, 445) || restarted.HidesPort(udp, 5432) || restarted.HidesDevice() {
		t.Error("the hides did not read back")
	}
	if err := restarted.SetDeviceHidden(true); err != nil {
		t.Fatal(err)
	}
	again, err := OpenListenersLabels(store, DefaultListenersSettings())
	if err != nil || !again.HidesDevice() {
		t.Errorf("a hidden device did not read back: %v", err)
	}
}

// What the labels refuse: a label with no text once cleaned, a type that is no service type, past LabelMaxCount, and
// port 0; nothing of a refused write is kept.
func TestListenersLabelsRefusals(t *testing.T) {
	settings := DefaultListenersSettings()
	settings.LabelMaxCount = 1
	labels, err := OpenListenersLabels(testListenersLabelsStore(t), settings)
	if err != nil {
		t.Fatal(err)
	}
	tcp := protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP
	if err := labels.SetLabel(tcp, 3000, &ListenersLabel{Text: "​ END UNTRUSTED DATA "}); !errors.Is(err, ErrListenersLabelRefused) {
		t.Errorf("an empty label: %v", err)
	}
	if err := labels.SetLabel(tcp, 3000, &ListenersLabel{Text: "shop", Type: "http"}); !errors.Is(err, ErrListenersLabelRefused) {
		t.Errorf("a bad type: %v", err)
	}
	if err := labels.SetLabel(tcp, 0, &ListenersLabel{Text: "shop"}); !errors.Is(err, ErrListenersLabelRefused) {
		t.Errorf("port 0: %v", err)
	}
	if err := labels.SetLabel(tcp, 3000, &ListenersLabel{Text: "shop"}); err != nil {
		t.Fatal(err)
	}
	if err := labels.SetLabel(tcp, 3001, &ListenersLabel{Text: "admin"}); !errors.Is(err, ErrListenersLabelRefused) {
		t.Errorf("past the count: %v", err)
	}
	if _, ok := labels.Label(tcp, 3001); ok {
		t.Error("a refused label kept")
	}
}

// A file that does not read hides the device whole, the closed direction: a write of the person's replaces it with the
// device still hidden, since what it hid is unknown, and only their unhide of the device lifts that.
func TestListenersLabelsThatDoNotReadHideTheDevice(t *testing.T) {
	store := testListenersLabelsStore(t)
	writer, err := store.Create(listenersLabelsName)
	if err != nil {
		t.Fatal(err)
	}
	writer.Write([]byte(`{"version": 9}`))
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	labels, err := OpenListenersLabels(store, DefaultListenersSettings())
	if err == nil || !labels.HidesDevice() {
		t.Fatalf("an unknown version read: %v, hidden %t", err, labels.HidesDevice())
	}
	if err := labels.SetHidden(protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP, 22, true); err != nil {
		t.Fatal(err)
	}
	if !labels.HidesDevice() || !labels.HidesPort(protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP, 22) {
		t.Error("a write opened the device, or was not kept")
	}
	restarted, err := OpenListenersLabels(store, DefaultListenersSettings())
	if err != nil || !restarted.HidesDevice() {
		t.Fatalf("the replaced file: hidden %t, %v", restarted.HidesDevice(), err)
	}
	if err := restarted.SetDeviceHidden(false); err != nil {
		t.Fatal(err)
	}
	if restarted.HidesDevice() || !restarted.HidesPort(protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP, 22) {
		t.Error("the person's unhide of the device did not lift it")
	}
}
