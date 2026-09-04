use std::error::Error;
use std::fmt::{Display, Formatter};
use std::time::Duration;

const BASIS_POINTS: u128 = 10_000;
const MAXIMUM_POLICY_DELAY: Duration = Duration::from_secs(3_600);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackoffPolicy {
    pub initial_delay: Duration,
    pub maximum_delay: Duration,
    pub maximum_attempts: u32,
    pub jitter_basis_points: u16,
}

impl BackoffPolicy {
    /// Validates that retries are finite and delays have operational bounds.
    ///
    /// # Errors
    ///
    /// Returns [`BackoffError::InvalidPolicy`] for zero, inverted or excessive
    /// limits.
    pub fn validate(&self) -> Result<(), BackoffError> {
        if self.initial_delay.is_zero()
            || self.maximum_delay < self.initial_delay
            || self.maximum_delay > MAXIMUM_POLICY_DELAY
            || self.maximum_attempts == 0
            || self.maximum_attempts > 32
            || self.jitter_basis_points > 5_000
        {
            return Err(BackoffError::InvalidPolicy);
        }
        Ok(())
    }

    /// Returns the bounded delay for a zero-based attempt. `entropy_sample`
    /// maps the inclusive range `0..=10_000` across the configured symmetric
    /// jitter interval. The caller supplies cryptographically secure or
    /// platform randomness, keeping this policy deterministic and testable.
    ///
    /// # Errors
    ///
    /// Returns a policy validation error or
    /// [`BackoffError::InvalidEntropySample`].
    pub fn delay(
        &self,
        attempt: u32,
        entropy_sample: u16,
    ) -> Result<Option<Duration>, BackoffError> {
        self.validate()?;
        if entropy_sample > 10_000 {
            return Err(BackoffError::InvalidEntropySample);
        }
        if attempt >= self.maximum_attempts {
            return Ok(None);
        }

        let multiplier = 1_u32.checked_shl(attempt).unwrap_or(u32::MAX);
        let base = self
            .initial_delay
            .checked_mul(multiplier)
            .unwrap_or(self.maximum_delay)
            .min(self.maximum_delay);
        let jitter = u128::from(self.jitter_basis_points);
        let sample = u128::from(entropy_sample);
        let factor = BASIS_POINTS - jitter + (2 * jitter * sample / BASIS_POINTS);
        let jittered_nanos = base.as_nanos() * factor / BASIS_POINTS;
        let bounded_nanos = jittered_nanos.min(self.maximum_delay.as_nanos());
        let delay = Duration::from_nanos(u64::try_from(bounded_nanos).unwrap_or(u64::MAX));
        Ok(Some(delay))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackoffError {
    InvalidPolicy,
    InvalidEntropySample,
}

impl Display for BackoffError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPolicy => formatter.write_str("invalid reconnect backoff policy"),
            Self::InvalidEntropySample => {
                formatter.write_str("entropy sample must be between 0 and 10000")
            }
        }
    }
}

impl Error for BackoffError {}
