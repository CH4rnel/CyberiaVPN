package telemetry

import (
	"errors"
	"fmt"
	"math"
	"unicode"
)

var (
	ErrInvalidMetric      = errors.New("invalid telemetry metric")
	ErrForbiddenAttribute = errors.New("forbidden telemetry attribute")
)

const (
	maximumAttributes     = 6
	maximumAttributeValue = 64
)

type MetricName string

const (
	ConnectionSuccess  MetricName = "connection_success"
	HandshakeLatencyMS MetricName = "handshake_latency_ms"
	ReconnectCount     MetricName = "reconnect_count"
	PacketLossRatio    MetricName = "packet_loss_ratio"
	RoundTripTimeMS    MetricName = "round_trip_time_ms"
)

var supportedMetrics = map[MetricName]struct{}{
	ConnectionSuccess:  {},
	HandshakeLatencyMS: {},
	ReconnectCount:     {},
	PacketLossRatio:    {},
	RoundTripTimeMS:    {},
}

var allowedAttributes = map[string]struct{}{
	"client_platform": {},
	"client_version":  {},
	"error_class":     {},
	"outcome":         {},
	"region":          {},
	"transport":       {},
}

// Metric is an aggregated operational observation. Attribute names are
// allowlisted so destinations, payloads and stable user identifiers cannot be
// added by convention alone.
type Metric struct {
	Name       MetricName
	Value      float64
	Attributes map[string]string
}

func (metric Metric) Validate() error {
	if _, supported := supportedMetrics[metric.Name]; !supported {
		return fmt.Errorf("%w: unsupported name %q", ErrInvalidMetric, metric.Name)
	}
	if math.IsNaN(metric.Value) || math.IsInf(metric.Value, 0) || metric.Value < 0 {
		return fmt.Errorf("%w: value must be finite and non-negative", ErrInvalidMetric)
	}
	switch metric.Name {
	case PacketLossRatio:
		if metric.Value > 1 {
			return fmt.Errorf("%w: packet loss ratio must be between zero and one", ErrInvalidMetric)
		}
	case ConnectionSuccess:
		if metric.Value != 0 && metric.Value != 1 {
			return fmt.Errorf("%w: connection success must be zero or one", ErrInvalidMetric)
		}
	case ReconnectCount:
		if math.Trunc(metric.Value) != metric.Value {
			return fmt.Errorf("%w: reconnect count must be an integer", ErrInvalidMetric)
		}
	}
	if len(metric.Attributes) > maximumAttributes {
		return fmt.Errorf("%w: too many attributes", ErrInvalidMetric)
	}
	for name, value := range metric.Attributes {
		if _, allowed := allowedAttributes[name]; !allowed {
			return fmt.Errorf("%w: %q", ErrForbiddenAttribute, name)
		}
		if value == "" || len(value) > maximumAttributeValue || !printableASCII(value) {
			return fmt.Errorf("%w: invalid %q attribute value", ErrInvalidMetric, name)
		}
	}
	return nil
}

func printableASCII(value string) bool {
	for _, character := range value {
		if character > unicode.MaxASCII || !unicode.IsPrint(character) {
			return false
		}
	}
	return true
}
