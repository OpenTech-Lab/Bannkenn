use crate::burst::categorize_reason;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SharedRiskCategory {
    pub category: String,
    pub distinct_ips: u32,
    pub distinct_agents: u32,
    pub event_count: u32,
    pub threshold_multiplier: f64,
    pub force_threshold: Option<u32>,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SharedRiskSnapshot {
    pub generated_at: String,
    pub window_secs: i64,
    pub global_risk_score: f64,
    pub global_threshold_multiplier: f64,
    pub categories: Vec<SharedRiskCategory>,
}

impl Default for SharedRiskSnapshot {
    fn default() -> Self {
        Self {
            generated_at: String::new(),
            window_secs: 600,
            global_risk_score: 0.0,
            global_threshold_multiplier: 1.0,
            categories: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharedRiskDecision {
    pub effective_threshold: Option<u32>,
    pub tags: Vec<String>,
}

impl SharedRiskSnapshot {
    pub fn apply(&self, base_threshold: u32, reason: &str) -> SharedRiskDecision {
        let mut effective = base_threshold;
        let mut applied = false;
        let mut tags = Vec::new();

        if self.global_threshold_multiplier < 0.999 {
            let global_threshold =
                scaled_threshold(base_threshold, self.global_threshold_multiplier);
            if global_threshold <= effective {
                effective = global_threshold;
                applied = true;
                tags.push("shared:global".to_string());
            }
        }

        let category = categorize_reason(reason);
        if let Some(shared_category) = self
            .categories
            .iter()
            .find(|item| item.category == category)
        {
            let category_threshold = shared_category.force_threshold.unwrap_or_else(|| {
                scaled_threshold(base_threshold, shared_category.threshold_multiplier)
            });

            if category_threshold <= effective {
                effective = category_threshold;
                applied = true;
                tags.push(shared_category.label.clone());
            }
        }

        if applied {
            tags.sort();
            tags.dedup();
            SharedRiskDecision {
                effective_threshold: Some(effective.max(1)),
                tags,
            }
        } else {
            SharedRiskDecision::default()
        }
    }
}

fn scaled_threshold(base: u32, multiplier: f64) -> u32 {
    ((base as f64) * multiplier).round().max(1.0) as u32
}

#[cfg(test)]
#[path = "../tests/unit/shared_risk_tests.rs"]
mod tests;
