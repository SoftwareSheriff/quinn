use std::{cmp, net::SocketAddr, time::Duration};

use crate::{congestion, TIMER_GRANULARITY};

/// Description of a particular network path
pub struct PathData {
    pub remote: SocketAddr,
    pub rtt: RttEstimator,
    /// Whether we're enabling ECN on outgoing packets
    pub sending_ecn: bool,
    /// Congestion controller state
    pub congestion: Box<dyn congestion::Controller>,
}

impl PathData {
    pub fn new(remote: SocketAddr, congestion: Box<dyn congestion::Controller>) -> Self {
        PathData {
            remote,
            rtt: RttEstimator::new(),
            sending_ecn: true,
            congestion,
        }
    }

    pub fn from_previous(remote: SocketAddr, prev: &PathData) -> Self {
        PathData {
            remote,
            rtt: prev.rtt,
            congestion: prev.congestion.clone_box(),
            sending_ecn: true,
        }
    }
}

#[derive(Copy, Clone)]
pub struct RttEstimator {
    /// The most recent RTT measurement made when receiving an ack for a previously unacked packet
    latest: Duration,
    /// The smoothed RTT of the connection, computed as described in RFC6298
    smoothed: Option<Duration>,
    /// The RTT variance, computed as described in RFC6298
    var: Duration,
    /// The minimum RTT seen in the connection, ignoring ack delay.
    min: Duration,
}

impl RttEstimator {
    fn new() -> Self {
        Self {
            latest: Duration::new(0, 0),
            smoothed: None,
            var: Duration::new(0, 0),
            min: Duration::new(u64::max_value(), 0),
        }
    }

    pub fn update(&mut self, ack_delay: Duration, rtt: Duration) {
        self.latest = rtt;
        // min_rtt ignores ack delay.
        self.min = cmp::min(self.min, self.latest);
        // Adjust for ack delay if it's plausible.
        if self.latest - self.min > ack_delay {
            self.latest -= ack_delay;
        }
        // Based on RFC6298.
        if let Some(smoothed) = self.smoothed {
            let var_sample = if smoothed > self.latest {
                smoothed - self.latest
            } else {
                self.latest - smoothed
            };
            self.var = (3 * self.var + var_sample) / 4;
            self.smoothed = Some((7 * smoothed + self.latest) / 8);
        } else {
            self.smoothed = Some(self.latest);
            self.var = self.latest / 2;
        }
    }

    pub fn get(&self) -> Duration {
        self.smoothed
            .map_or(self.latest, |x| cmp::max(x, self.latest))
    }

    pub fn pto_base(&self) -> Option<Duration> {
        self.smoothed
            .map(|srtt| srtt + cmp::max(4 * self.var, TIMER_GRANULARITY))
    }
}
