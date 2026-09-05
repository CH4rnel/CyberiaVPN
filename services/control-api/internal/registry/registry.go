package registry

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

var (
	ErrAlreadyRegistered = errors.New("node is already registered")
	ErrNotFound          = errors.New("node is not registered")
)

type Status string

const (
	StatusProvisioning Status = "provisioning"
	StatusHealthy      Status = "healthy"
	StatusRestricted   Status = "restricted"
	StatusQuarantined  Status = "quarantined"
)

type Transport string

const (
	TransportWireGuard Transport = "wireguard"
)

// Node contains control-plane metadata. It deliberately contains no private
// key material and no user traffic data.
type Node struct {
	ID           string         `json:"id"`
	Region       string         `json:"region"`
	Endpoint     netip.AddrPort `json:"endpoint"`
	Transports   []Transport    `json:"transports"`
	Status       Status         `json:"status"`
	RegisteredAt time.Time      `json:"registered_at"`
}

func (node Node) Validate() error {
	if !validSlug(node.ID) {
		return errors.New("node ID must be a lowercase slug")
	}
	if !validSlug(node.Region) {
		return errors.New("region must be a lowercase slug")
	}
	address := node.Endpoint.Addr().Unmap()
	if !node.Endpoint.IsValid() || node.Endpoint.Port() == 0 ||
		address.IsUnspecified() || address.IsMulticast() || node.Endpoint.Addr().Zone() != "" {
		return errors.New("endpoint must contain an unscoped unicast IP address and nonzero port")
	}
	if len(node.Transports) == 0 {
		return errors.New("at least one transport is required")
	}
	for _, transport := range node.Transports {
		if transport != TransportWireGuard {
			return fmt.Errorf("unsupported transport %q", transport)
		}
	}
	if node.Status != StatusProvisioning && node.Status != StatusHealthy &&
		node.Status != StatusRestricted && node.Status != StatusQuarantined {
		return fmt.Errorf("unsupported node status %q", node.Status)
	}
	return nil
}

type MemoryRegistry struct {
	mu    sync.RWMutex
	nodes map[string]Node
}

func NewMemoryRegistry() *MemoryRegistry {
	return &MemoryRegistry{nodes: make(map[string]Node)}
}

func (registry *MemoryRegistry) Register(node Node) error {
	if err := node.Validate(); err != nil {
		return fmt.Errorf("validate node: %w", err)
	}

	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.nodes[node.ID]; exists {
		return ErrAlreadyRegistered
	}
	registry.nodes[node.ID] = cloneNode(node)
	return nil
}

func (registry *MemoryRegistry) Get(id string) (Node, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	node, exists := registry.nodes[id]
	if !exists {
		return Node{}, ErrNotFound
	}
	return cloneNode(node), nil
}

func (registry *MemoryRegistry) List() []Node {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	nodes := make([]Node, 0, len(registry.nodes))
	for _, node := range registry.nodes {
		nodes = append(nodes, cloneNode(node))
	}
	slices.SortFunc(nodes, func(left, right Node) int {
		return strings.Compare(left.ID, right.ID)
	})
	return nodes
}

func cloneNode(node Node) Node {
	node.Transports = slices.Clone(node.Transports)
	return node
}

func validSlug(value string) bool {
	if value == "" || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}
