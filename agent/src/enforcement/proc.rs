use crate::enforcement::{EnforcementAction, EnforcementFuture, EnforcementOutcome, Enforcer};
use anyhow::Context;
use tokio::process::Command;

#[derive(Debug, Default)]
pub struct ProcessEnforcer;

impl Enforcer for ProcessEnforcer {
    fn name(&self) -> &'static str {
        "proc"
    }

    fn supports(&self, action: &EnforcementAction) -> bool {
        matches!(
            action,
            EnforcementAction::SuspendProcess { .. }
                | EnforcementAction::ResumeProcess { .. }
                | EnforcementAction::KillProcess { .. }
        )
    }

    fn execute<'a>(
        &'a self,
        action: &'a EnforcementAction,
        dry_run: bool,
    ) -> EnforcementFuture<'a> {
        Box::pin(async move {
            let (pid, signal) = match action {
                EnforcementAction::SuspendProcess { pid, .. } => (*pid, "-STOP"),
                EnforcementAction::ResumeProcess { pid, .. } => (*pid, "-CONT"),
                EnforcementAction::KillProcess { pid, .. } => (*pid, "-KILL"),
                _ => {
                    return Ok(EnforcementOutcome {
                        action: action.clone(),
                        enforcer: self.name().to_string(),
                        applied: false,
                        dry_run,
                        detail: "unsupported process action".to_string(),
                    });
                }
            };

            if dry_run {
                return Ok(EnforcementOutcome {
                    action: action.clone(),
                    enforcer: self.name().to_string(),
                    applied: false,
                    dry_run: true,
                    detail: format!("dry-run process signal {} to pid {}", signal, pid),
                });
            }

            let status = Command::new("kill")
                .arg(signal)
                .arg(pid.to_string())
                .status()
                .await
                .with_context(|| format!("failed to execute kill {} {}", signal, pid))?;

            Ok(EnforcementOutcome {
                action: action.clone(),
                enforcer: self.name().to_string(),
                applied: status.success(),
                dry_run: false,
                detail: if status.success() {
                    format!("sent {} to pid {}", signal, pid)
                } else {
                    format!("kill {} {} exited with {}", signal, pid, status)
                },
            })
        })
    }
}
