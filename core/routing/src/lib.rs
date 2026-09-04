//! Deterministic node and transport selection for Cyberia VPN.

#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::error::Error;
use std::fmt::{Display, Formatter};

mod selector;

pub use selector::{RouteSelector, SelectionPolicy};

const QUALITY_MAX: u32 = 10_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCandidate {
    pub id: String,
    pub measurements: Measurements,
}

/// Probe results normalized by explicit policy limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Measurements {
    pub available: bool,
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub packet_loss_basis_points: u16,
    pub available_bandwidth_mbps: u32,
}

/// Relative importance of each quality dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScoreWeights {
    pub latency: u16,
    pub jitter: u16,
    pub packet_loss: u16,
    pub bandwidth: u16,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self {
            latency: 40,
            jitter: 15,
            packet_loss: 30,
            bandwidth: 15,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScoreLimits {
    pub maximum_latency_ms: u32,
    pub maximum_jitter_ms: u32,
    pub target_bandwidth_mbps: u32,
}

impl Default for ScoreLimits {
    fn default() -> Self {
        Self {
            maximum_latency_ms: 1_000,
            maximum_jitter_ms: 500,
            target_bandwidth_mbps: 100,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RoutingPolicy {
    pub weights: ScoreWeights,
    pub limits: ScoreLimits,
}

impl RoutingPolicy {
    /// Returns a stable integer quality score in the range `0..=10_000`.
    ///
    /// # Errors
    ///
    /// Returns [`RoutingError::InvalidPolicy`] when no weight is assigned or a
    /// normalization limit is zero. Invalid measurements are rejected too.
    pub fn score(&self, measurements: Measurements) -> Result<u32, RoutingError> {
        self.validate()?;
        if !measurements.available {
            return Ok(0);
        }
        if measurements.packet_loss_basis_points > 10_000 {
            return Err(RoutingError::InvalidMeasurements(
                "packet loss exceeds 100 percent",
            ));
        }

        let latency = inverse_quality(measurements.latency_ms, self.limits.maximum_latency_ms);
        let jitter = inverse_quality(measurements.jitter_ms, self.limits.maximum_jitter_ms);
        let loss = QUALITY_MAX - u32::from(measurements.packet_loss_basis_points);
        let bandwidth = direct_quality(
            measurements.available_bandwidth_mbps,
            self.limits.target_bandwidth_mbps,
        );
        let total_weight = self.total_weight();
        let weighted_sum = u64::from(latency) * u64::from(self.weights.latency)
            + u64::from(jitter) * u64::from(self.weights.jitter)
            + u64::from(loss) * u64::from(self.weights.packet_loss)
            + u64::from(bandwidth) * u64::from(self.weights.bandwidth);

        Ok(u32::try_from(weighted_sum / u64::from(total_weight)).unwrap_or(QUALITY_MAX))
    }

    /// Selects the highest-scoring available node, using its ID as a stable
    /// tie-breaker so the same observations always produce the same answer.
    ///
    /// # Errors
    ///
    /// Returns a validation error or [`RoutingError::NoAvailableNodes`].
    pub fn select<'a>(
        &self,
        candidates: &'a [NodeCandidate],
    ) -> Result<&'a NodeCandidate, RoutingError> {
        let mut ranked = candidates
            .iter()
            .filter(|node| node.measurements.available)
            .map(|node| self.score(node.measurements).map(|score| (node, score)));

        let mut best = ranked.next().ok_or(RoutingError::NoAvailableNodes)??;
        for candidate in ranked {
            let candidate = candidate?;
            if compare_rank(candidate, best) == Ordering::Greater {
                best = candidate;
            }
        }
        Ok(best.0)
    }

    fn validate(&self) -> Result<(), RoutingError> {
        if self.total_weight() == 0 {
            return Err(RoutingError::InvalidPolicy("all weights are zero"));
        }
        if self.limits.maximum_latency_ms == 0
            || self.limits.maximum_jitter_ms == 0
            || self.limits.target_bandwidth_mbps == 0
        {
            return Err(RoutingError::InvalidPolicy(
                "normalization limits must be non-zero",
            ));
        }
        Ok(())
    }

    fn total_weight(&self) -> u32 {
        u32::from(self.weights.latency)
            + u32::from(self.weights.jitter)
            + u32::from(self.weights.packet_loss)
            + u32::from(self.weights.bandwidth)
    }
}

fn inverse_quality(value: u32, maximum: u32) -> u32 {
    let normalized = u64::from(value) * u64::from(QUALITY_MAX) / u64::from(maximum);
    QUALITY_MAX.saturating_sub(u32::try_from(normalized).unwrap_or(u32::MAX))
}

fn direct_quality(value: u32, target: u32) -> u32 {
    let normalized = u64::from(value) * u64::from(QUALITY_MAX) / u64::from(target);
    u32::try_from(normalized)
        .unwrap_or(u32::MAX)
        .min(QUALITY_MAX)
}

fn compare_rank(left: (&NodeCandidate, u32), right: (&NodeCandidate, u32)) -> Ordering {
    left.1
        .cmp(&right.1)
        .then_with(|| right.0.id.cmp(&left.0.id))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoutingError {
    InvalidPolicy(&'static str),
    InvalidMeasurements(&'static str),
    NoAvailableNodes,
}

impl Display for RoutingError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPolicy(reason) => write!(formatter, "invalid routing policy: {reason}"),
            Self::InvalidMeasurements(reason) => {
                write!(formatter, "invalid node measurements: {reason}")
            }
            Self::NoAvailableNodes => formatter.write_str("no available nodes"),
        }
    }
}

impl Error for RoutingError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, latency_ms: u32) -> NodeCandidate {
        NodeCandidate {
            id: id.to_owned(),
            measurements: Measurements {
                available: true,
                latency_ms,
                jitter_ms: 5,
                packet_loss_basis_points: 0,
                available_bandwidth_mbps: 100,
            },
        }
    }

    #[test]
    fn prefers_lower_latency_when_other_signals_match() {
        let nodes = [node("de-2", 90), node("de-1", 40)];

        let selected = RoutingPolicy::default().select(&nodes).unwrap();

        assert_eq!(selected.id, "de-1");
    }

    #[test]
    fn never_selects_an_unavailable_node() {
        let mut unavailable = node("fast-but-down", 1);
        unavailable.measurements.available = false;
        let nodes = [unavailable, node("healthy", 80)];

        let selected = RoutingPolicy::default().select(&nodes).unwrap();

        assert_eq!(selected.id, "healthy");
    }

    #[test]
    fn breaks_equal_score_ties_by_node_id() {
        let nodes = [node("node-b", 50), node("node-a", 50)];

        let selected = RoutingPolicy::default().select(&nodes).unwrap();

        assert_eq!(selected.id, "node-a");
    }

    #[test]
    fn rejects_impossible_packet_loss() {
        let measurements = Measurements {
            packet_loss_basis_points: 10_001,
            ..node("bad-probe", 50).measurements
        };

        assert_eq!(
            RoutingPolicy::default().score(measurements),
            Err(RoutingError::InvalidMeasurements(
                "packet loss exceeds 100 percent"
            ))
        );
    }
}
