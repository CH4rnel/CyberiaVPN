package telemetry_test

import (
	"errors"
	"math"
	"testing"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/telemetry"
)

func TestAcceptsLowCardinalityOperationalMetric(t *testing.T) {
	metric := telemetry.Metric{
		Name:  telemetry.ConnectionSuccess,
		Value: 1,
		Attributes: map[string]string{
			"region":    "de-fra",
			"transport": "wireguard",
			"outcome":   "success",
		},
	}

	if err := metric.Validate(); err != nil {
		t.Fatalf("validate metric: %v", err)
	}
}

func TestRejectsDestinationTelemetry(t *testing.T) {
	metric := telemetry.Metric{
		Name:  telemetry.ConnectionSuccess,
		Value: 1,
		Attributes: map[string]string{
			"destination_domain": "example.com",
		},
	}

	err := metric.Validate()

	if !errors.Is(err, telemetry.ErrForbiddenAttribute) {
		t.Fatalf("error = %v, want ErrForbiddenAttribute", err)
	}
}

func TestRejectsStableUserIdentifier(t *testing.T) {
	metric := telemetry.Metric{
		Name:       telemetry.ReconnectCount,
		Value:      1,
		Attributes: map[string]string{"device_id": "laptop-1"},
	}

	err := metric.Validate()

	if !errors.Is(err, telemetry.ErrForbiddenAttribute) {
		t.Fatalf("error = %v, want ErrForbiddenAttribute", err)
	}
}

func TestRejectsNonFiniteMetricValue(t *testing.T) {
	metric := telemetry.Metric{Name: telemetry.HandshakeLatencyMS, Value: math.Inf(1)}

	err := metric.Validate()

	if !errors.Is(err, telemetry.ErrInvalidMetric) {
		t.Fatalf("error = %v, want ErrInvalidMetric", err)
	}
}

func TestRejectsUnboundedAttributeValue(t *testing.T) {
	metric := telemetry.Metric{
		Name:       telemetry.ConnectionSuccess,
		Value:      1,
		Attributes: map[string]string{"error_class": string(make([]byte, 65))},
	}

	err := metric.Validate()

	if !errors.Is(err, telemetry.ErrInvalidMetric) {
		t.Fatalf("error = %v, want ErrInvalidMetric", err)
	}
}

func TestMetricSpecificValueRanges(t *testing.T) {
	tests := []struct {
		name  telemetry.MetricName
		value float64
		valid bool
	}{
		{telemetry.PacketLossRatio, 0, true},
		{telemetry.PacketLossRatio, 0.5, true},
		{telemetry.PacketLossRatio, 1, true},
		{telemetry.PacketLossRatio, 1.01, false},
		{telemetry.ConnectionSuccess, 0, true},
		{telemetry.ConnectionSuccess, 1, true},
		{telemetry.ConnectionSuccess, 0.5, false},
		{telemetry.ConnectionSuccess, 2, false},
		{telemetry.ReconnectCount, 0, true},
		{telemetry.ReconnectCount, 12, true},
		{telemetry.ReconnectCount, 1.5, false},
		{telemetry.HandshakeLatencyMS, 1.5, true},
		{telemetry.RoundTripTimeMS, 2.5, true},
	}
	for _, test := range tests {
		err := (telemetry.Metric{Name: test.name, Value: test.value}).Validate()
		if test.valid && err != nil {
			t.Errorf("%s=%v: %v", test.name, test.value, err)
		}
		if !test.valid && !errors.Is(err, telemetry.ErrInvalidMetric) {
			t.Errorf("%s=%v: error = %v, want ErrInvalidMetric", test.name, test.value, err)
		}
	}
}
