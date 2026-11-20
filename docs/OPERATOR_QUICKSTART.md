# Operator quick start

This guide takes a new workspace from local startup to its first evidence-backed investigation. It uses offline data by default. Connecting a cloud provider is optional.

## 1. Start the local workspace

Install the project and launch the API from the repository root:

```powershell
python -m pip install -e .
python -m cloudshield.api
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765). Keep the service bound to loopback for local development. For the hardened local production profile, follow [deployment operations](DEPLOYMENT_OPERATIONS.md).

## 2. Choose a data path

- **Offline evaluation:** select Run simulation on the overview. Choose a scenario and run it. Simulated events are labelled and do not contact AWS or Azure.
- **File import:** import supported CloudTrail, Security Hub or Azure Activity Log JSON exports. Review the import result and event counts.
- **Cloud collection:** open Data sources and configure a workspace-scoped, read-only identity. Follow [cloud operations](CLOUD_OPERATIONS.md) and the provider-specific least-privilege guidance before enabling collection.

Do not paste access keys, client secrets, private keys or session tokens into chat, issue trackers, screenshots or public files. Use the provider identity mechanisms and secret-management guidance documented by the project.

## 3. Review detection results

Open Detections to inspect matched rules, severity, rationale and ATT&CK references. Open Detection library to review the supported rule set and known coverage boundaries. A rule match is an investigation lead, not proof of compromise.

## 4. Investigate and preserve evidence

Open Incidents and select a case to review its associated events and findings. Use Evidence vault to inspect normalized records and fingerprints. Export a bundle and verify it using the bundle verification control. A matching hash proves integrity relative to the bundle manifest; it does not authenticate the source system.

## 5. Review operational controls

- Data sources shows provider configuration and collection status.
- Alerts & response exposes response requests, approvals, dry-run results and the kill-switch state.
- Account security contains the workspace sign-in controls.
- The overview readiness panel reports provider and collector state. An empty or stale status is not a successful provider acceptance test.

## 6. Production and acceptance boundaries

Keep the cloud response kill switch enabled. This build does not include reviewed production write adapters, so cloud execution is intentionally unavailable. Do not grant write permissions to the collection identity.

A successful local test run does not establish live provider acceptance, multi-host availability, off-host disaster recovery, independent penetration-test completion or production detection accuracy. Use the [Phases 28–31 acceptance plan](PHASES_28_31_ACCEPTANCE_PLAN.md) for required external evidence and sign-off.

## Troubleshooting

- **API unavailable:** confirm the server is running and the browser is using the configured local URL.
- **No events:** run an offline simulation or import a supported audit export.
- **Provider not connected:** verify tenant/account identifiers, role trust or workload identity, read-only permissions, and the provider's audit-log availability.
- **Collector unhealthy:** inspect the server and worker logs, heartbeat age, lease state and configured polling bounds before restarting workers.
- **Evidence verification fails:** retain the original bundle, inspect the reported manifest errors and export a fresh bundle if appropriate. Do not edit signed evidence in place.
