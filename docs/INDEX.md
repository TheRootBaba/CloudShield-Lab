# CloudShield documentation

This is the maintained entry point for operators, contributors, reviewers and evaluators.

## Start here

| Need | Document |
|---|---|
| Understand the project, run it and see its boundaries | [Project README](../README.md) |
| Understand components, trust boundaries and data flows | [Architecture](ARCHITECTURE.md) |
| Understand current capabilities and limitations | [Current capabilities](CURRENT_CAPABILITIES.md) |
| Configure and operate cloud connections, collectors and response controls | [Cloud operations](CLOUD_OPERATIONS.md) |
| Deploy, back up and recover the local production profile | [Deployment operations](DEPLOYMENT_OPERATIONS.md) |
| Review security assumptions and threats | [Security threat model](SECURITY_THREAT_MODEL.md) |
| Review release gates and assurance evidence | [Release assurance](RELEASE_ASSURANCE.md) |
| Review supported detection patterns | [Detection coverage](DETECTION_COVERAGE.md) |
| Understand evaluation methodology and fixture limitations | [Detection evaluation](DETECTION_EVALUATION.md) |
| Verify exported evidence and signatures | [Evidence custody](EVIDENCE_CUSTODY.md) |

## Operator guides

- [Operator quick start and first investigation](OPERATOR_QUICKSTART.md)
- [Multi-user authentication and workspace isolation](MULTI_USER_AUTH.md)
- [Firebase authentication](FIREBASE_AUTH.md)
- [AWS and Azure provider configuration](CLOUD_OPERATIONS.md)
- [Backup and recovery runbook](FINALIZATION_RUNBOOK.md)
- [Deployment runbook](DEPLOYMENT_OPERATIONS.md)
- [Cloud operations runbook](CLOUD_OPERATIONS.md)

## Engineering references

- [Phase 27 documentation and evidence record](PHASE_27_DOCUMENTATION_AND_EVIDENCE.md)
- [Cloud adapter design](CLOUD_ADAPTER_DESIGN.md)
- [Attack-path correlation semantics](ATTACK_PATH_CORRELATION.md)
- [Threat model](THREAT_MODEL.md)
- [Detection rules and coverage](DETECTION_COVERAGE.md)
- [Engineering roadmap](ROADMAP.md)
- [Phases 28-31 acceptance plan](PHASES_28_31_ACCEPTANCE_PLAN.md)
- [Phases 28-31 acceptance-gate diagram](diagrams/phase-28-31-acceptance.svg)
- [Phases 23–26 implementation and acceptance record](PHASES_23_26_IMPLEMENTATION_REPORT.md)
- [Project screenshots and evidence](../evidence/README.md)
- [Acceptance evidence and local verification capture](../evidence/acceptance/README.md)

## Release discipline

CloudShield is a local-first security engineering lab and portfolio project. It is not a certified production CSPM/SIEM and does not claim comprehensive threat coverage. Read the capability boundaries and release gates before connecting a real cloud account or enabling an operational workflow.

A passing test suite proves the tested software paths only. It does not establish live AWS/Azure acceptance, production detection accuracy, successful external backup restoration, high availability or independent security assurance.
