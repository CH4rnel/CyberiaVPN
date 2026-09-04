package registry_test

import (
	"errors"
	"testing"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/registry"
)

func TestNodeLifecycleAllowsHealthyProvisioning(t *testing.T) {
	store := registry.NewMemoryRegistry()
	if err := store.Register(testNode("de-fra-1")); err != nil {
		t.Fatalf("register node: %v", err)
	}

	err := store.Transition("de-fra-1", registry.StatusProvisioning, registry.StatusHealthy)

	if err != nil {
		t.Fatalf("transition node: %v", err)
	}
	node, err := store.Get("de-fra-1")
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if node.Status != registry.StatusHealthy {
		t.Errorf("status = %q, want healthy", node.Status)
	}
}

func TestNodeLifecycleRejectsStaleExpectedState(t *testing.T) {
	store := registry.NewMemoryRegistry()
	if err := store.Register(testNode("de-fra-1")); err != nil {
		t.Fatalf("register node: %v", err)
	}

	err := store.Transition("de-fra-1", registry.StatusHealthy, registry.StatusRestricted)

	if !errors.Is(err, registry.ErrStateConflict) {
		t.Fatalf("error = %v, want ErrStateConflict", err)
	}
}

func TestQuarantinedNodeCannotReturnInPlace(t *testing.T) {
	store := registry.NewMemoryRegistry()
	if err := store.Register(testNode("de-fra-1")); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := store.Transition("de-fra-1", registry.StatusProvisioning, registry.StatusQuarantined); err != nil {
		t.Fatalf("quarantine node: %v", err)
	}

	err := store.Transition("de-fra-1", registry.StatusQuarantined, registry.StatusHealthy)

	if !errors.Is(err, registry.ErrInvalidTransition) {
		t.Fatalf("error = %v, want ErrInvalidTransition", err)
	}
}

func TestHealthyNodeCanBeRestrictedAndRecovered(t *testing.T) {
	store := registry.NewMemoryRegistry()
	if err := store.Register(testNode("de-fra-1")); err != nil {
		t.Fatalf("register node: %v", err)
	}
	transitions := [][2]registry.Status{
		{registry.StatusProvisioning, registry.StatusHealthy},
		{registry.StatusHealthy, registry.StatusRestricted},
		{registry.StatusRestricted, registry.StatusHealthy},
	}
	for _, transition := range transitions {
		if err := store.Transition("de-fra-1", transition[0], transition[1]); err != nil {
			t.Fatalf("transition %q -> %q: %v", transition[0], transition[1], err)
		}
	}
}
