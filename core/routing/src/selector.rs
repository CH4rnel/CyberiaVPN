use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::{NodeCandidate, RoutingError, RoutingPolicy};

/// Stability controls applied on top of stateless quality scoring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectionPolicy {
    pub minimum_dwell_time: Duration,
    pub switch_margin: u32,
    pub failure_threshold: u32,
    pub circuit_cooldown: Duration,
}

impl Default for SelectionPolicy {
    fn default() -> Self {
        Self {
            minimum_dwell_time: Duration::from_secs(30),
            switch_margin: 500,
            failure_threshold: 3,
            circuit_cooldown: Duration::from_secs(60),
        }
    }
}

#[derive(Clone, Debug)]
struct CircuitState {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

/// Stateful selector that prevents route flapping and temporarily excludes
/// repeatedly failing nodes.
#[derive(Clone, Debug)]
pub struct RouteSelector {
    scoring: RoutingPolicy,
    stability: SelectionPolicy,
    current: Option<(String, Instant)>,
    circuits: HashMap<String, CircuitState>,
}

impl RouteSelector {
    pub fn new(scoring: RoutingPolicy, stability: SelectionPolicy) -> Self {
        Self {
            scoring,
            stability,
            current: None,
            circuits: HashMap::new(),
        }
    }

    /// Selects a route while respecting open circuits, dwell time and the
    /// improvement margin required to replace a healthy current route.
    ///
    /// # Errors
    ///
    /// Returns a scoring error or [`RoutingError::NoAvailableNodes`] when all
    /// candidates are unavailable or temporarily excluded.
    pub fn select<'a>(
        &mut self,
        candidates: &'a [NodeCandidate],
        now: Instant,
    ) -> Result<&'a NodeCandidate, RoutingError> {
        let eligible: Vec<NodeCandidate> = candidates
            .iter()
            .filter(|candidate| !self.circuit_is_open(&candidate.id, now))
            .cloned()
            .collect();
        let best_id = self.scoring.select(&eligible)?.id.clone();
        let best = find_candidate(candidates, &best_id).ok_or(RoutingError::NoAvailableNodes)?;

        let current_candidate = self
            .current
            .as_ref()
            .and_then(|(node_id, _)| find_candidate(candidates, node_id));
        if let Some(((current_id, selected_at), current)) =
            self.current.as_ref().zip(current_candidate)
        {
            let current_is_eligible =
                current.measurements.available && !self.circuit_is_open(current_id, now);
            if current_is_eligible {
                let dwell_elapsed = now.saturating_duration_since(*selected_at)
                    >= self.stability.minimum_dwell_time;
                let current_score = self.scoring.score(current.measurements)?;
                let best_score = self.scoring.score(best.measurements)?;
                let enough_improvement =
                    best_score >= current_score.saturating_add(self.stability.switch_margin);

                if !dwell_elapsed || !enough_improvement {
                    return Ok(current);
                }
            }
        }

        if self.current.as_ref().map(|current| &current.0) != Some(&best.id) {
            self.current = Some((best.id.clone(), now));
        }
        Ok(best)
    }

    /// Records a failed connection and opens the node's circuit after the
    /// configured number of consecutive failures.
    pub fn record_failure(&mut self, node_id: &str, now: Instant) {
        let state = self
            .circuits
            .entry(node_id.to_owned())
            .or_insert(CircuitState {
                consecutive_failures: 0,
                open_until: None,
            });
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= self.stability.failure_threshold {
            state.open_until = now.checked_add(self.stability.circuit_cooldown);
        }
    }

    /// A successful connection closes the circuit and resets its failure count.
    pub fn record_success(&mut self, node_id: &str) {
        self.circuits.remove(node_id);
    }

    fn circuit_is_open(&self, node_id: &str, now: Instant) -> bool {
        self.circuits
            .get(node_id)
            .and_then(|state| state.open_until)
            .is_some_and(|open_until| now < open_until)
    }
}

fn find_candidate<'a>(candidates: &'a [NodeCandidate], node_id: &str) -> Option<&'a NodeCandidate> {
    candidates.iter().find(|candidate| candidate.id == node_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Measurements;

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
    fn keeps_current_node_during_minimum_dwell_time() {
        let start = Instant::now();
        let mut selector = RouteSelector::new(RoutingPolicy::default(), SelectionPolicy::default());
        let initial = [node("a", 40), node("b", 80)];
        assert_eq!(selector.select(&initial, start).unwrap().id, "a");

        let changed = [node("a", 200), node("b", 10)];
        let selected = selector.select(&changed, start + Duration::from_secs(5));

        assert_eq!(selected.unwrap().id, "a");
    }

    #[test]
    fn requires_a_meaningful_improvement_after_dwell_time() {
        let start = Instant::now();
        let mut selector = RouteSelector::new(RoutingPolicy::default(), SelectionPolicy::default());
        let initial = [node("a", 50), node("b", 60)];
        selector.select(&initial, start).unwrap();

        let slightly_better = [node("a", 50), node("b", 49)];
        let selected = selector.select(&slightly_better, start + Duration::from_secs(31));

        assert_eq!(selected.unwrap().id, "a");
    }

    #[test]
    fn opens_circuit_after_repeated_failures() {
        let now = Instant::now();
        let policy = SelectionPolicy {
            minimum_dwell_time: Duration::ZERO,
            switch_margin: 0,
            failure_threshold: 2,
            circuit_cooldown: Duration::from_secs(60),
        };
        let mut selector = RouteSelector::new(RoutingPolicy::default(), policy);
        selector.record_failure("fast", now);
        selector.record_failure("fast", now);
        let nodes = [node("fast", 10), node("fallback", 100)];

        assert_eq!(selector.select(&nodes, now).unwrap().id, "fallback");
        assert_eq!(
            selector
                .select(&nodes, now + Duration::from_secs(61))
                .unwrap()
                .id,
            "fast"
        );
    }
}
