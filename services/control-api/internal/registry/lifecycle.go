package registry

import (
	"errors"
	"fmt"
)

var (
	ErrStateConflict     = errors.New("node state changed concurrently")
	ErrInvalidTransition = errors.New("invalid node state transition")
)

// Transition atomically changes a node state when the caller's expected state
// is still current. Quarantine is intentionally terminal: recovery requires a
// revoked node to be rebuilt and registered with a new identity.
func (registry *MemoryRegistry) Transition(id string, expected, target Status) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	node, exists := registry.nodes[id]
	if !exists {
		return ErrNotFound
	}
	if node.Status != expected {
		return fmt.Errorf("%w: current=%q expected=%q", ErrStateConflict, node.Status, expected)
	}
	if !transitionAllowed(expected, target) {
		return fmt.Errorf("%w: %q -> %q", ErrInvalidTransition, expected, target)
	}
	node.Status = target
	registry.nodes[id] = node
	return nil
}

func transitionAllowed(current, target Status) bool {
	switch current {
	case StatusProvisioning:
		return target == StatusHealthy || target == StatusQuarantined
	case StatusHealthy:
		return target == StatusRestricted || target == StatusQuarantined
	case StatusRestricted:
		return target == StatusHealthy || target == StatusQuarantined
	case StatusQuarantined:
		return false
	default:
		return false
	}
}
