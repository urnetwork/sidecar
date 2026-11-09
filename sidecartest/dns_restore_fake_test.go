package sidecartest

import (
	"context"
	"testing"

	"github.com/urnetwork/sidecar"
)

// The fake holds the restore store's contract (D-TEST-2).
func TestFakeDnsRestoreStorePassesItsSuite(t *testing.T) {
	store := NewFakeDnsRestoreStore(nil)
	labelCount := 0
	RunDnsRestoreStoreSuite(t, &DnsRestoreStoreSubject{
		Store: store,
		NewRoot: func(ctx context.Context) (string, error) {
			return "r" + sidecar.NewId().String()[24:] + ".example.", nil
		},
		NewNetwork: func(ctx context.Context, root string) (string, sidecar.Id, error) {
			labelCount += 1
			label := "net" + string(rune('a'+labelCount%26)) + sidecar.NewId().String()[30:]
			networkId := sidecar.NewId()
			store.SetLabel(root, label, networkId)
			return label, networkId, nil
		},
		OpenCase: func(ctx context.Context, networkId sidecar.Id) error {
			store.SetOpenCase(networkId, true)
			return nil
		},
		AdminEventCount: func(ctx context.Context, networkId sidecar.Id, incidentId sidecar.Id) (int, error) {
			count := 0
			for _, event := range store.AdminEvents() {
				if event.NetworkId == networkId && event.IncidentId == incidentId {
					count += 1
				}
			}
			return count, nil
		},
	})
}

// The same, as the server's store answers before dns_ns exists.
func TestFakeDnsRestoreStoreWithNoNsStatePassesItsSuite(t *testing.T) {
	store := NewFakeDnsRestoreStore(nil)
	store.SetNsStateUnavailable(true)
	RunDnsRestoreStoreSuite(t, &DnsRestoreStoreSubject{
		Store: store,
		NewRoot: func(ctx context.Context) (string, error) {
			return "r" + sidecar.NewId().String()[24:] + ".example.", nil
		},
		NewNetwork: func(ctx context.Context, root string) (string, sidecar.Id, error) {
			label := "net" + sidecar.NewId().String()[28:]
			networkId := sidecar.NewId()
			store.SetLabel(root, label, networkId)
			return label, networkId, nil
		},
		OpenCase: func(ctx context.Context, networkId sidecar.Id) error {
			store.SetOpenCase(networkId, true)
			return nil
		},
		AdminEventCount: func(ctx context.Context, networkId sidecar.Id, incidentId sidecar.Id) (int, error) {
			count := 0
			for _, event := range store.AdminEvents() {
				if event.NetworkId == networkId && event.IncidentId == incidentId {
					count += 1
				}
			}
			return count, nil
		},
	})
}
