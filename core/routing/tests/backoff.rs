use std::time::Duration;

use cyberia_routing::{BackoffError, BackoffPolicy};

fn policy() -> BackoffPolicy {
    BackoffPolicy {
        initial_delay: Duration::from_secs(1),
        maximum_delay: Duration::from_secs(8),
        maximum_attempts: 4,
        jitter_basis_points: 2_000,
    }
}

#[test]
fn increases_delay_exponentially_and_caps_it() {
    let policy = policy();

    assert_eq!(
        policy.delay(0, 5_000).unwrap(),
        Some(Duration::from_secs(1))
    );
    assert_eq!(
        policy.delay(1, 5_000).unwrap(),
        Some(Duration::from_secs(2))
    );
    assert_eq!(
        policy.delay(3, 5_000).unwrap(),
        Some(Duration::from_secs(8))
    );
}

#[test]
fn stops_after_bounded_number_of_attempts() {
    assert_eq!(policy().delay(4, 5_000).unwrap(), None);
}

#[test]
fn applies_symmetric_jitter() {
    let policy = policy();

    assert_eq!(
        policy.delay(1, 0).unwrap(),
        Some(Duration::from_millis(1_600))
    );
    assert_eq!(
        policy.delay(1, 10_000).unwrap(),
        Some(Duration::from_millis(2_400))
    );
}

#[test]
fn rejects_out_of_range_entropy_sample() {
    assert_eq!(
        policy().delay(0, 10_001),
        Err(BackoffError::InvalidEntropySample)
    );
}

#[test]
fn rejects_unbounded_or_zero_policy() {
    let invalid = BackoffPolicy {
        maximum_attempts: 0,
        ..policy()
    };

    assert_eq!(invalid.validate(), Err(BackoffError::InvalidPolicy));
}
