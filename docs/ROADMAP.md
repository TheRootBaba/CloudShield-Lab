# Engineering roadmap

CloudShield is a local-first cloud security lab. The roadmap tracks engineering milestones and external acceptance gates separately.

## Delivered software milestones

- **Phases 1–20:** detection pipeline, investigation workflow, evidence bundles, evaluation, tenant-aware authentication and provider adapters; see the engineering references in [the documentation index](INDEX.md).
- **Phase 21:** workspace-scoped AWS/Azure connection configuration, scheduled bounded collection, alerting, response request/approval records and production foundations.
- **Phases 23–26:** guarded response planning, approvals and kill switch; worker leasing and metrics; security-assurance preparation; expanded Azure detection rules.
- **Phase 27:** documentation, architecture visuals, sanitized demo media, screenshot evidence, evidence manifest and public project presentation.

## Remaining acceptance milestones

The consolidated execution checklist, acceptance evidence requirements and local verification runner are maintained in [the Phases 28?31 acceptance package](PHASES_28_31_ACCEPTANCE_PLAN.md). The accompanying [acceptance-gate diagram](diagrams/phase-28-31-acceptance.svg) visualizes the required sequence.

### Phase 28 — Live provider acceptance
- Validate AWS AssumeRole and Azure workload identity with dedicated sandbox tenants.
- Verify tenant isolation, permission scope, bounded collection and failure handling.
- Record provider-side evidence and remove all temporary test resources.
- Exit: signed acceptance report for both providers, with no cross-tenant access.

### Phase 29 — Production response adapters
- Implement only explicitly approved action-specific AWS/Azure adapters.
- Add provider-state preconditions, dry-run parity, blast-radius limits and compensation/rollback.
- Test quorum, idempotency, kill switch and partial-failure behavior in isolated accounts.
- Exit: independently reviewed containment drills with before/after and rollback evidence.

### Phase 30 — Distributed operations and recovery
- Move worker coordination and durable jobs to PostgreSQL or a managed queue.
- Centralize logs, metrics, paging and SLO/error-budget dashboards.
- Run load, failover, restore and disaster-recovery drills.
- Exit: documented recovery objectives demonstrated in a production-like environment.

### Phase 31 — Independent security and detection assurance
- Complete penetration and tenant-isolation testing.
- Resolve and independently retest critical/high findings.
- Expand privacy-reviewed labelled telemetry and measure per-rule precision/recall.
- Exit: signed independent assurance report and documented detection-quality baseline.

## Release rule

Passing local tests does not close live-provider, production resilience or independent security gates. Keep cloud writes disabled until Phase 29 is accepted. Do not describe the platform as production-certified before Phases 28–31 have passed their external acceptance criteria.
