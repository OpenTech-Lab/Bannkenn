pub mod cgroup;
pub mod proc;
pub mod tc;

use crate::config::ContainmentConfig;
use crate::enforcement::cgroup::CgroupEnforcer;
use crate::enforcement::proc::ProcessEnforcer;
use crate::enforcement::tc::TrafficControlEnforcer;
use anyhow::Result;
use std::future::Future;
use std::pin::Pin;

type EnforcementFuture<'a> = Pin<Box<dyn Future<Output = Result<EnforcementOutcome>> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementAction {
    ApplyIoThrottle {
        pid: Option<u32>,
        watched_root: String,
    },
    ApplyNetworkThrottle {
        pid: Option<u32>,
        watched_root: String,
    },
    SuspendProcess {
        pid: u32,
        watched_root: String,
    },
    ResumeProcess {
        pid: u32,
        watched_root: String,
    },
    #[allow(dead_code)]
    KillProcess {
        pid: u32,
        watched_root: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementOutcome {
    pub action: EnforcementAction,
    pub enforcer: String,
    pub applied: bool,
    pub dry_run: bool,
    pub detail: String,
}

pub trait Enforcer: Send + Sync {
    fn name(&self) -> &'static str;
    fn supports(&self, action: &EnforcementAction) -> bool;
    fn execute<'a>(&'a self, action: &'a EnforcementAction, dry_run: bool)
        -> EnforcementFuture<'a>;
}

#[derive(Debug)]
pub struct EnforcementDispatcher {
    cgroup: CgroupEnforcer,
    tc: TrafficControlEnforcer,
    proc: ProcessEnforcer,
}

impl EnforcementDispatcher {
    pub fn from_config(config: &ContainmentConfig, server_url: &str) -> Self {
        Self {
            cgroup: CgroupEnforcer::new(config),
            tc: TrafficControlEnforcer::new(config, server_url),
            proc: ProcessEnforcer,
        }
    }

    pub async fn execute_all(
        &self,
        actions: &[EnforcementAction],
        dry_run: bool,
    ) -> Result<Vec<EnforcementOutcome>> {
        let mut outcomes = Vec::with_capacity(actions.len());

        for action in actions {
            let enforcer = self.select_enforcer(action);
            let outcome = if let Some(enforcer) = enforcer {
                enforcer.execute(action, dry_run).await?
            } else {
                EnforcementOutcome {
                    action: action.clone(),
                    enforcer: "none".to_string(),
                    applied: false,
                    dry_run,
                    detail: "no enforcer registered for action".to_string(),
                }
            };
            outcomes.push(outcome);
        }

        Ok(outcomes)
    }

    fn select_enforcer(&self, action: &EnforcementAction) -> Option<&dyn Enforcer> {
        let enforcers: [&dyn Enforcer; 3] = [&self.cgroup, &self.tc, &self.proc];
        enforcers
            .into_iter()
            .find(|enforcer| enforcer.supports(action))
    }
}

impl Default for EnforcementDispatcher {
    fn default() -> Self {
        let config = ContainmentConfig::default();
        Self::from_config(&config, "")
    }
}
