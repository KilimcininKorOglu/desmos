//! Prometheus exposition format (text/plain; version=0.0.4) renderer.
//!
//! Renders Desmos metrics in the Prometheus text format.  Metrics:
//!
//! ## Counters (monotonically increasing)
//!
//! - `desmos_bytes_tx{interface="..."}` — total bytes transmitted
//! - `desmos_bytes_rx{interface="..."}` — total bytes received
//! - `desmos_packets_tx{interface="..."}` — total packets transmitted
//! - `desmos_packets_rx{interface="..."}` — total packets received
//! - `desmos_errors_total{interface="...",type="..."}` — error counts
//!
//! ## Gauges (point-in-time)
//!
//! - `desmos_link_rtt_us{interface="..."}` — current RTT in microseconds
//! - `desmos_link_loss_pct{interface="..."}` — current loss percentage
//! - `desmos_link_jitter_us{interface="..."}` — current jitter in microseconds

use std::fmt::Write;

/// Content-Type for Prometheus text exposition format.
pub const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// A single metric sample with labels.
#[derive(Debug, Clone)]
pub struct Sample {
    /// Metric name (e.g. `desmos_bytes_tx`).
    pub name: String,
    /// Label pairs (e.g. `[("interface", "eth0")]`).
    pub labels: Vec<(String, String)>,
    /// Metric value.
    pub value: f64,
}

/// A metric family (HELP + TYPE + samples).
#[derive(Debug, Clone)]
pub struct MetricFamily {
    /// Metric name.
    pub name: String,
    /// HELP string.
    pub help: String,
    /// Prometheus type: "counter", "gauge", "histogram", "summary".
    pub metric_type: &'static str,
    /// All samples for this metric.
    pub samples: Vec<Sample>,
}

/// Render a set of metric families to Prometheus text format.
pub fn render(families: &[MetricFamily]) -> String {
    let mut out = String::with_capacity(1024);

    for family in families {
        let _ = writeln!(out, "# HELP {} {}", family.name, family.help);
        let _ = writeln!(out, "# TYPE {} {}", family.name, family.metric_type);

        for sample in &family.samples {
            let _ = write!(out, "{}", sample.name);
            if !sample.labels.is_empty() {
                out.push('{');
                for (i, (k, v)) in sample.labels.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    let _ = write!(out, "{}=\"{}\"", k, escape_label_value(v));
                }
                out.push('}');
            }
            // Render integer-valued floats without decimal.
            if sample.value.fract() == 0.0 && sample.value.abs() < (1i64 << 53) as f64 {
                let _ = writeln!(out, " {}", sample.value as i64);
            } else {
                let _ = writeln!(out, " {}", sample.value);
            }
        }

        out.push('\n');
    }

    out
}

/// Escape a Prometheus label value (backslash, double-quote, newline).
fn escape_label_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// Build the standard Desmos metric families.
///
/// In production, `interfaces` would come from the real link stats.
/// Each interface produces counter and gauge samples.
pub fn build_desmos_metrics(interfaces: &[InterfaceStats]) -> Vec<MetricFamily> {
    let mut families = Vec::new();

    // ---- Counters ----------------------------------------------------------

    families.push(MetricFamily {
        name: "desmos_bytes_tx".into(),
        help: "Total bytes transmitted through the tunnel".into(),
        metric_type: "counter",
        samples: interfaces
            .iter()
            .map(|i| Sample {
                name: "desmos_bytes_tx".into(),
                labels: vec![("interface".into(), i.name.clone())],
                value: i.tx_bytes as f64,
            })
            .collect(),
    });

    families.push(MetricFamily {
        name: "desmos_bytes_rx".into(),
        help: "Total bytes received through the tunnel".into(),
        metric_type: "counter",
        samples: interfaces
            .iter()
            .map(|i| Sample {
                name: "desmos_bytes_rx".into(),
                labels: vec![("interface".into(), i.name.clone())],
                value: i.rx_bytes as f64,
            })
            .collect(),
    });

    families.push(MetricFamily {
        name: "desmos_packets_tx".into(),
        help: "Total packets transmitted".into(),
        metric_type: "counter",
        samples: interfaces
            .iter()
            .map(|i| Sample {
                name: "desmos_packets_tx".into(),
                labels: vec![("interface".into(), i.name.clone())],
                value: i.tx_packets as f64,
            })
            .collect(),
    });

    families.push(MetricFamily {
        name: "desmos_packets_rx".into(),
        help: "Total packets received".into(),
        metric_type: "counter",
        samples: interfaces
            .iter()
            .map(|i| Sample {
                name: "desmos_packets_rx".into(),
                labels: vec![("interface".into(), i.name.clone())],
                value: i.rx_packets as f64,
            })
            .collect(),
    });

    families.push(MetricFamily {
        name: "desmos_errors_total".into(),
        help: "Total errors by type".into(),
        metric_type: "counter",
        samples: interfaces
            .iter()
            .flat_map(|i| {
                vec![
                    Sample {
                        name: "desmos_errors_total".into(),
                        labels: vec![
                            ("interface".into(), i.name.clone()),
                            ("type".into(), "decrypt".into()),
                        ],
                        value: i.decrypt_errors as f64,
                    },
                    Sample {
                        name: "desmos_errors_total".into(),
                        labels: vec![
                            ("interface".into(), i.name.clone()),
                            ("type".into(), "replay".into()),
                        ],
                        value: i.replay_drops as f64,
                    },
                ]
            })
            .collect(),
    });

    // ---- Gauges ------------------------------------------------------------

    families.push(MetricFamily {
        name: "desmos_link_rtt_us".into(),
        help: "Current RTT in microseconds".into(),
        metric_type: "gauge",
        samples: interfaces
            .iter()
            .map(|i| Sample {
                name: "desmos_link_rtt_us".into(),
                labels: vec![("interface".into(), i.name.clone())],
                value: i.rtt_us as f64,
            })
            .collect(),
    });

    families.push(MetricFamily {
        name: "desmos_link_loss_pct".into(),
        help: "Current packet loss percentage".into(),
        metric_type: "gauge",
        samples: interfaces
            .iter()
            .map(|i| Sample {
                name: "desmos_link_loss_pct".into(),
                labels: vec![("interface".into(), i.name.clone())],
                value: i.loss_pct,
            })
            .collect(),
    });

    families.push(MetricFamily {
        name: "desmos_link_jitter_us".into(),
        help: "Current jitter in microseconds".into(),
        metric_type: "gauge",
        samples: interfaces
            .iter()
            .map(|i| Sample {
                name: "desmos_link_jitter_us".into(),
                labels: vec![("interface".into(), i.name.clone())],
                value: i.jitter_us as f64,
            })
            .collect(),
    });

    families
}

/// Per-interface statistics snapshot for Prometheus rendering.
#[derive(Debug, Clone)]
pub struct InterfaceStats {
    pub name: String,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub decrypt_errors: u64,
    pub replay_drops: u64,
    pub rtt_us: u64,
    pub loss_pct: f64,
    pub jitter_us: u64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_interfaces() -> Vec<InterfaceStats> {
        vec![
            InterfaceStats {
                name: "eth0".into(),
                tx_bytes: 1_234_567_890,
                rx_bytes: 987_654_321,
                tx_packets: 100_000,
                rx_packets: 95_000,
                decrypt_errors: 5,
                replay_drops: 2,
                rtt_us: 4210,
                loss_pct: 0.1,
                jitter_us: 320,
            },
            InterfaceStats {
                name: "wlan0".into(),
                tx_bytes: 500_000,
                rx_bytes: 400_000,
                tx_packets: 10_000,
                rx_packets: 9_500,
                decrypt_errors: 0,
                replay_drops: 0,
                rtt_us: 12_500,
                loss_pct: 1.5,
                jitter_us: 800,
            },
        ]
    }

    #[test]
    fn render_contains_help_and_type() {
        let families = build_desmos_metrics(&sample_interfaces());
        let text = render(&families);
        assert!(text.contains("# HELP desmos_bytes_tx Total bytes transmitted"));
        assert!(text.contains("# TYPE desmos_bytes_tx counter"));
        assert!(text.contains("# HELP desmos_link_rtt_us Current RTT"));
        assert!(text.contains("# TYPE desmos_link_rtt_us gauge"));
    }

    #[test]
    fn render_contains_samples_with_labels() {
        let families = build_desmos_metrics(&sample_interfaces());
        let text = render(&families);
        assert!(text.contains("desmos_bytes_tx{interface=\"eth0\"} 1234567890"));
        assert!(text.contains("desmos_bytes_rx{interface=\"wlan0\"} 400000"));
        assert!(text.contains("desmos_link_rtt_us{interface=\"eth0\"} 4210"));
    }

    #[test]
    fn render_error_counters_have_type_label() {
        let families = build_desmos_metrics(&sample_interfaces());
        let text = render(&families);
        assert!(text.contains("desmos_errors_total{interface=\"eth0\",type=\"decrypt\"} 5"));
        assert!(text.contains("desmos_errors_total{interface=\"eth0\",type=\"replay\"} 2"));
        assert!(text.contains("desmos_errors_total{interface=\"wlan0\",type=\"decrypt\"} 0"));
    }

    #[test]
    fn render_gauge_with_fractional_value() {
        let families = build_desmos_metrics(&sample_interfaces());
        let text = render(&families);
        // loss_pct = 0.1 should render with decimal
        assert!(text.contains("desmos_link_loss_pct{interface=\"eth0\"} 0.1"));
        assert!(text.contains("desmos_link_loss_pct{interface=\"wlan0\"} 1.5"));
    }

    #[test]
    fn render_empty_interfaces() {
        let families = build_desmos_metrics(&[]);
        let text = render(&families);
        // Should still have HELP/TYPE lines but no samples.
        assert!(text.contains("# HELP desmos_bytes_tx"));
        assert!(!text.contains("interface="));
    }

    #[test]
    fn escape_label_value_special_chars() {
        assert_eq!(escape_label_value("normal"), "normal");
        assert_eq!(escape_label_value("has\"quote"), "has\\\"quote");
        assert_eq!(escape_label_value("has\\slash"), "has\\\\slash");
        assert_eq!(escape_label_value("has\nnewline"), "has\\nnewline");
    }

    #[test]
    fn render_single_family() {
        let families = vec![MetricFamily {
            name: "test_metric".into(),
            help: "A test metric".into(),
            metric_type: "gauge",
            samples: vec![Sample {
                name: "test_metric".into(),
                labels: vec![("host".into(), "srv1".into())],
                value: 42.0,
            }],
        }];
        let text = render(&families);
        assert_eq!(
            text,
            "# HELP test_metric A test metric\n# TYPE test_metric gauge\ntest_metric{host=\"srv1\"} 42\n\n"
        );
    }

    #[test]
    fn metric_family_count() {
        let families = build_desmos_metrics(&sample_interfaces());
        // 5 counters (bytes_tx, bytes_rx, packets_tx, packets_rx, errors_total)
        // 3 gauges (rtt_us, loss_pct, jitter_us)
        assert_eq!(families.len(), 8);
    }

    #[test]
    fn all_families_have_correct_types() {
        let families = build_desmos_metrics(&sample_interfaces());
        let counters: Vec<_> = families.iter().filter(|f| f.metric_type == "counter").collect();
        let gauges: Vec<_> = families.iter().filter(|f| f.metric_type == "gauge").collect();
        assert_eq!(counters.len(), 5);
        assert_eq!(gauges.len(), 3);
    }
}
