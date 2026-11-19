# Dual-provider and operations extension report

**Date:** 19 November 2026
**Repository:** `TheRootBaba/CloudShield-Lab`
**Branch:** `feat/phases-15-20-offline-completion`
**Scope:** complete the code/documentation work possible without external production accounts or independent reviewers; AWS and Azure live collection remain opt-in.

## Executive summary

CloudShield now offers AWS and Microsoft Azure as two provider options. Azure support includes bounded subscription ARM resource metadata inventory and Azure Activity Log control-plane ingestion, normalized events, two conservative Azure detections, CLI commands, provider status and admin-only API routes. AWS pagination now has repeated-token protection, explicit standard retries for live clients and partial-failure reporting. A verified SQLite online backup/restore CLI, dependency lock for the container, hardened local Docker Compose profile, CI source/dependency scanning and optional trusted timestamp/WORM design have also been added.

This is not a declaration of hosted production readiness. No live AWS or Azure APIs were called, no cloud resources were created or modified, and no hosting was provisioned.

## Phase delivery status

| Phase | Code/docs delivered in this extension | Remaining external gate |
|---|---|---|
| 15 — Application security | Existing role-token API auth/RBAC, bounded request validation, rate limits, security headers and mutation audit remain covered; provider collection endpoints are admin-only when role tokens are configured. | Browser login/session lifecycle, MFA/SSO, expiring/revocable sessions, tenant isolation, distributed rate limiting, managed secrets and independent penetration testing. Still loopback-only. |
| 16 — Evidence custody | Existing versioned manifests and Ed25519 verification retained; automated SQLite backup creates a SHA-256 sidecar manifest, checks integrity, refuses overwrite and restores only to a new path. RFC 3161/WORM integration design documented. | Trusted TSA and immutable archive provider/policy not selected or integrated; unsigned colocated backup manifest is not independent trust. |
| 17 — Detection quality | Added two Azure rules, ATT&CK mappings, positive/negative fixtures and a 30-case corpus; severity/confidence limits remain documented. | Representative independently labelled production telemetry and statistically meaningful calibration/accuracy. |
| 18 — Cloud integrations | AWS and Azure adapters are opt-in, bounded, read-only and mock-tested. Azure inventory and Activity Logs use Azure SDK clients and `DefaultAzureCredential`; AWS token pagination and partial failures hardened. | Live validation of AWS/Azure permissions, subscriptions/accounts, throttling, pagination and inventory coverage. No live API calls in this change. |
| 19 — Deployment/operations | Dependency-pinned runtime lock, local Dockerfile/Compose profile, non-root user, read-only root FS, dropped capabilities, persistent data volume, loopback-only host port, online backup/restore CLI and runbooks. | Local Docker daemon was unavailable, so the image could not be built here; CI container-build job is configured. Hosted monitoring/alerting, production secret integration and actual operational restore exercise remain external. |
| 20 — Final assurance | Updated release checklist, risk/limitations docs, dual-provider setup, timestamp/WORM design and regression tests. | Independent review/penetration test, production load test, external restore/incident exercise, and production sign-off. |

## Provider capabilities

### AWS

- Existing CloudTrail `LookupEvents` one-shot collector and bounded EC2/security-group/S3-name/IAM metadata inventory remain explicitly disabled by default.
- Live botocore clients use standard retries with four total attempts.
- Pagination stops safely on repeated continuation tokens; successful pages are retained and partial failures are reported.
- Inventory `complete` remains false because its resource coverage is intentionally partial; `collection_complete` describes only whether the bounded requested operations completed without truncation/failure.

### Microsoft Azure

- Optional dependencies: `azure-identity`, `azure-mgmt-resource`, `azure-mgmt-monitor`.
- Resource inventory: `Microsoft.Resources/subscriptions/resources/read`.
- Activity Log collection: `Microsoft.Insights/eventtypes/values/read`.
- Auth: Azure SDK `DefaultAzureCredential`; CloudShield does not accept or store client secrets.
- Environment opt-in: `CLOUDSHIELD_ENABLE_AZURE_COLLECTION=1`; explicit subscription scope via `AZURE_SUBSCRIPTION_ID`.
- CLI: `cloudshield azure-inventory` and `cloudshield azure-activity-logs`.
- API: `GET /api/providers`, `POST /api/collector/azure/inventory`, `POST /api/collector/azure/activity-logs` (admin role when tokens are configured).
- Coverage is one subscription and control-plane Activity Logs plus ARM resource metadata. Defender for Cloud, Entra ID sign-ins/audit, data-plane logs, management groups and effective permission analysis are not implemented.

## Verification performed locally

Development machine: Windows, Python 3.14; project and optional AWS/Azure/signing dependencies installed in an isolated `.verify-venv`.

| Check | Result |
|---|---|
| Python compileall | Passed |
| Python unit/integration suite | **95 tests passed** |
| Detection evaluation | **30/30 curated cases passed** across 15 rules; fixture micro precision/recall/specificity/F1 = 1.0 on this corpus only |
| Python dependency audit | `pip-audit --skip-editable`: no known vulnerabilities in installed AWS/Azure/signing dependency set |
| Bandit source scan | Passed with zero findings after review of the explicit container-only bind exception |
| npm production dependency audit | 0 vulnerabilities |
| Vite production build | Passed; 407.27 kB main JS and 471.22 kB overview chunk |
| Terraform format | Passed |
| Terraform secure root validate | Passed |
| Terraform vulnerable training root validate | Passed |
| Compose YAML | Parsed; host port assertion confirms `127.0.0.1:8765:8765` |
| `git diff --check` | Passed |
| Docker image build | Local Docker daemon unavailable; GitHub Actions run #33 built the image successfully and validated Compose configuration (no image push). |

Azure SDK modules and both management clients were imported/constructed locally without making network requests. Provider behavior tests use injected fake clients. All AWS tests use fake clients. No AWS identity or Azure account validation was performed.

## Cost and cloud boundary

Cloud collection flags remain disabled by default. No AWS or Azure credentials were used for a live call, no cloud API calls were made, and no cloud resources or hosted services were created/modified/deleted. Cloud spend initiated by this change: **$0**. Future read-only API validation still needs an active provider account, least-privilege identity, explicit scope and a separately approved cost/request boundary; read-only is not a universal guarantee of zero provider-side cost.

## How to enable locally (only after account and permission review)

AWS: install `python -m pip install -e ".[aws]"`, configure a dedicated least-privilege AWS profile, then set `CLOUDSHIELD_ENABLE_AWS_COLLECTOR=1` for CloudTrail or `CLOUDSHIELD_ENABLE_AWS_INVENTORY=1` for inventory.

Azure: install `python -m pip install -e ".[azure]"`, authenticate with `az login` or another supported credential source, set `AZURE_SUBSCRIPTION_ID`, then set `CLOUDSHIELD_ENABLE_AZURE_COLLECTION=1`.

Keep both disabled for offline use. Never use root/Owner/Contributor credentials. Do not commit credentials or share them in chat.

## Final release boundary

The core local multi-user tranche is implemented with browser sessions and isolated workspaces. The production HTTPS stack is a validated configuration template, not a deployed service. Do not expose the listener directly. Phases 15?20 cannot be marked fully production-complete until enterprise identity, live provider, independent security and real-host operational gates are performed.
