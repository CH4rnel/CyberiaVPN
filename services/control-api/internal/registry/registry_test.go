package registry_test

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/registry"
)

func TestRegisterAndGetNode(t *testing.T) {
	store := registry.NewMemoryRegistry()
	node := testNode("de-fra-1")

	if err := store.Register(node); err != nil {
		t.Fatalf("register node: %v", err)
	}
	got, err := store.Get(node.ID)
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if got.ID != node.ID || got.Endpoint != node.Endpoint {
		t.Errorf("got node %+v, want %+v", got, node)
	}
}

func TestRejectsDuplicateIdentity(t *testing.T) {
	store := registry.NewMemoryRegistry()
	node := testNode("de-fra-1")
	if err := store.Register(node); err != nil {
		t.Fatalf("register first node: %v", err)
	}

	err := store.Register(node)

	if !errors.Is(err, registry.ErrAlreadyRegistered) {
		t.Fatalf("error = %v, want ErrAlreadyRegistered", err)
	}
}

func TestListIsStableAndDoesNotExposeMutableState(t *testing.T) {
	store := registry.NewMemoryRegistry()
	for _, id := range []string{"de-fra-2", "de-fra-1"} {
		if err := store.Register(testNode(id)); err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
	}

	nodes := store.List()
	nodes[0].Transports[0] = "modified"

	if nodes[0].ID != "de-fra-1" || nodes[1].ID != "de-fra-2" {
		t.Fatalf("nodes are not sorted: %+v", nodes)
	}
	stored, err := store.Get("de-fra-1")
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if stored.Transports[0] != registry.TransportWireGuard {
		t.Errorf("stored transport was mutated: %q", stored.Transports[0])
	}
}

func TestRejectsInvalidControlPlaneMetadata(t *testing.T) {
	node := testNode("INVALID ID")

	err := registry.NewMemoryRegistry().Register(node)

	if err == nil {
		t.Fatal("expected invalid node ID to be rejected")
	}
}

func testNode(id string) registry.Node {
	return registry.Node{
		ID:           id,
		Region:       "de-fra",
		Endpoint:     netip.MustParseAddrPort("192.0.2.10:51820"),
		Transports:   []registry.Transport{registry.TransportWireGuard},
		Status:       registry.StatusProvisioning,
		RegisteredAt: time.Unix(1_788_563_400, 0).UTC(),
	}
}

func TestRejectsUnusableNodeEndpoints(t *testing.T) {
	for _, address := range []string{"0.0.0.0:51820", "[::]:51820", "224.0.0.1:51820", "[ff02::1]:51820", "[::ffff:0.0.0.0]:51820", "[fe80::1%eth0]:51820"} {
		t.Run(address, func(t *testing.T) {
			node := testNode("node-1")
			node.Endpoint = netip.MustParseAddrPort(address)
			store := registry.NewMemoryRegistry()
			if err := store.Register(node); err == nil {
				t.Fatal("accepted unusable endpoint")
			}
			if len(store.List()) != 0 {
				t.Fatal("invalid node was stored")
			}
		})
	}
}
