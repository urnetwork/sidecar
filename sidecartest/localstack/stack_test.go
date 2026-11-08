//go:build sidecar_localstack

// The conformance suites on the real stores of local/, and that those stores are §22.4's shape. Each
// fails when the stack is down: run them through local/stack.sh test. A real store keeps real time, so
// the suites' ttl cases wait, and nothing else here does.

package localstack

import (
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest/blobsuite"
	"github.com/urnetwork/sidecar/sidecartest/redissuite"
)

func newStackRedis(t *testing.T) *Redis {
	redis, err := NewRedis(t.Context(), nil)
	if err != nil {
		t.Fatalf("the local stack's Redis Cluster: %v", err)
	}
	t.Cleanup(redis.Close)
	return redis
}

func newStackBlobs(t *testing.T) *BlobStore {
	store, err := NewBlobStore(t.Context(), nil)
	if err != nil {
		t.Fatalf("the local stack's MinIO: %v", err)
	}
	t.Cleanup(store.Close)
	return store
}

func TestRedisClusterConforms(t *testing.T) {
	redissuite.Run(t, &redissuite.Target{
		Redis:        newStackRedis(t),
		Pass:         time.Sleep,
		EventTimeout: 10 * time.Second,
	})
}

func TestMinioConforms(t *testing.T) {
	store := newStackBlobs(t)
	blobsuite.RunStore(t, store)
	for _, clusterId := range append(store.MetadataClusterIds(), store.settings.SegmentCluster.ClusterId) {
		cluster, err := store.Cluster(clusterId)
		if err != nil {
			t.Fatal(err)
		}
		// Settle stays nil on a stock image, and the suite names each case that waits for the fork.
		// LastModified is whole seconds, and the store runs on a VM's clock.
		blobsuite.Run(t, &blobsuite.Target{
			Cluster:        cluster,
			Now:            time.Now,
			ClockTolerance: 2 * time.Second,
		})
	}
}

// §22.4: 3 masters, no replicas, on 8.10.2, with production's keyspace classes.
func TestRedisClusterIsTheDesignsShape(t *testing.T) {
	redis := newStackRedis(t)
	masters := redis.Masters()
	if len(masters) != 3 {
		t.Fatalf("masters %v", masters)
	}
	for _, address := range masters {
		replies, err := redis.roundTrip(t.Context(), address, redis.settings.CallTimeout,
			redisArgs("INFO", "server"), redisArgs("INFO", "replication"), redisArgs("CONFIG", "GET", "notify-keyspace-events"))
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`(?m)^redis_version:8\.10\.2\r?$`).Match(replies[0].text) {
			t.Errorf("%s: version: %s", address, replies[0].text)
		}
		if !regexp.MustCompile(`(?m)^role:master\r?$`).Match(replies[1].text) ||
			!regexp.MustCompile(`(?m)^connected_slaves:0\r?$`).Match(replies[1].text) {
			t.Errorf("%s: replication: %s", address, replies[1].text)
		}
		classes := strings.Split(string(replies[2].values[1].text), "")
		slices.Sort(classes)
		if strings.Join(classes, "") != "$Kgsx" {
			t.Errorf("%s: keyspace classes %q", address, replies[2].values[1].text)
		}
	}
}

// §22.4: one process, 8 drives, parity 4, so drive quorum behaves as in production.
func TestMinioIsTheDesignsShape(t *testing.T) {
	store := newStackBlobs(t)
	cluster := store.clusters[store.settings.MetadataClusters[0].ClusterId]
	answer, err := cluster.sendAdmin(t.Context(), http.MethodGet, "/minio/admin/v3/info")
	if err != nil {
		t.Fatal(err)
	}
	defer answer.close()
	if answer.response.StatusCode != http.StatusOK {
		t.Fatalf("admin info: %v", newS3Failure(answer.response))
	}
	info := struct {
		Backend struct {
			Type             string `json:"backendType"`
			OnlineDisks      int    `json:"onlineDisks"`
			OfflineDisks     int    `json:"offlineDisks"`
			StandardScParity int    `json:"standardSCParity"`
		} `json:"backend"`
		Servers []struct {
			Drives []struct{} `json:"drives"`
		} `json:"servers"`
	}{}
	if err := json.NewDecoder(answer.response.Body).Decode(&info); err != nil {
		t.Fatal(err)
	}
	backend := info.Backend
	if backend.Type != "Erasure" || backend.OnlineDisks != 8 || backend.OfflineDisks != 0 || backend.StandardScParity != 4 {
		t.Errorf("backend %+v", backend)
	}
	if len(info.Servers) != 1 || len(info.Servers[0].Drives) != 8 {
		t.Errorf("servers %+v", info.Servers)
	}
}
