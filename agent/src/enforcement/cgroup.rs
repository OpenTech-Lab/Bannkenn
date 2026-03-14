use crate::enforcement::{EnforcementAction, EnforcementFuture, EnforcementOutcome, Enforcer};

#[derive(Debug, Default)]
pub struct CgroupEnforcer;

impl Enforcer for CgroupEnforcer {
    fn name(&self) -> &'static str {
        "cgroup"
    }

    fn supports(&self, action: &EnforcementAction) -> bool {
        matches!(action, EnforcementAction::ApplyIoThrottle { .. })
    }

    fn execute<'a>(
        &'a self,
        action: &'a EnforcementAction,
        dry_run: bool,
    ) -> EnforcementFuture<'a> {
        Box::pin(async move {
            Ok(EnforcementOutcome {
                action: action.clone(),
                enforcer: self.name().to_string(),
                applied: false,
                dry_run,
                detail: if dry_run {
                    "dry-run I/O throttle via cgroups v2".to_string()
                } else {
                    "cgroups v2 I/O throttling is not implemented yet".to_string()
                },
            })
        })
    }
}
