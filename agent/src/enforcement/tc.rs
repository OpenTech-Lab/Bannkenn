use crate::enforcement::{EnforcementAction, EnforcementFuture, EnforcementOutcome, Enforcer};

#[derive(Debug, Default)]
pub struct TrafficControlEnforcer;

impl Enforcer for TrafficControlEnforcer {
    fn name(&self) -> &'static str {
        "tc"
    }

    fn supports(&self, action: &EnforcementAction) -> bool {
        matches!(action, EnforcementAction::ApplyNetworkThrottle { .. })
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
                    "dry-run network throttle via tc/netem".to_string()
                } else {
                    "tc/netem throttling is not implemented yet".to_string()
                },
            })
        })
    }
}
