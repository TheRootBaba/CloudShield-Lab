# Azure provider integration

## Delivered adapter

CloudShield now supports Azure as a second provider alongside AWS. The initial Azure adapter is deliberately narrow and read-only:

- Subscription-scoped Azure Resource Manager inventory via `ResourceManagementClient.resources.list()`.
- Subscription Activity Log collection over a bounded UTC lookback window via `MonitorManagementClient.activity_logs.list()`.
- Continuation-page and record caps, provider SDK retry policy, UTC timestamps, subscription/resource provenance, partial-failure reporting and explicit truncation status.
- Azure event normalization and conservative rules for role-assignment writes and deletion of diagnostic settings.

This is not an Azure CSPM or a complete Azure inventory. It does not query Microsoft Defender for Cloud alerts, Entra ID sign-in/audit logs, data-plane logs, effective RBAC permissions, network reachability, management-group subscriptions or every resource provider. Activity Logs are control-plane signals; they do not replace resource diagnostic/data-plane logs.

## Local setup (no cloud calls until opted in)

Install Azure SDK extras:

```powershell
python -m pip install -e ".[azure]"
```

Authenticate using the Azure CLI (`az login`) or a supported `DefaultAzureCredential` source such as a managed identity or service principal environment. Set the subscription scope:

```powershell
$env:AZURE_SUBSCRIPTION_ID="00000000-0000-0000-0000-000000000000"
```

The adapter uses Azure SDK `DefaultAzureCredential`; CloudShield does not accept or persist client secrets. The SDK credential chain can use developer credentials or workload/managed identity depending on the environment. Prefer a managed identity in hosted environments and a dedicated least-privilege identity for validation.

Live collection is disabled unless explicitly enabled in the process environment:

```powershell
$env:CLOUDSHIELD_ENABLE_AZURE_COLLECTION="1"
cloudshield azure-inventory --max-pages 10 --max-records 2000 --output artifacts/azure-inventory.json
cloudshield azure-activity-logs --lookback-hours 24 --max-pages 10 --max-records 2000 --output artifacts/azure-activity.json
```

The single-user local API also exposes `GET /api/providers`, `POST /api/collector/azure/inventory` and `POST /api/collector/azure/activity-logs`; that legacy path uses `AZURE_SUBSCRIPTION_ID`. In Firebase multi-user mode, the subscription and identity are loaded from the authenticated workspace connection record; the request body cannot choose another tenant or subscription.

## Multi-user workspace connection path (Phase 21)

The CLI and explicit single-user local adapter may use Azure SDK `DefaultAzureCredential` for an operator's one-shot command. The shared Firebase/multi-user API and scheduled worker do **not** use that shared credential chain. They read the current workspace's tenant, subscription and client ID and instantiate either `ManagedIdentityCredential(client_id=...)` or `WorkloadIdentityCredential(tenant_id=..., client_id=..., token_file_path=...)`. They do not fall back to Azure CLI, developer credentials or client secrets. The UI requires a client ID and the global registry prevents reusing the same identity tuple in another workspace. A workspace administrator must test both ARM resource-read and Activity Log-read permissions before enabling polling.

## Permissions and boundaries

The intended minimum read permissions are:

- Resource inventory: `Microsoft.Resources/subscriptions/resources/read` (normally supplied by the built-in Reader role at the subscription scope).
- Activity Logs: `Microsoft.Insights/eventtypes/values/read` (normally supplied by Monitoring Reader at the subscription scope).

Review effective permissions in the target tenant before enabling. Do not grant Contributor, Owner, write, delete or role-assignment permissions. Do not use tenant-wide or management-group scope unless separately designed and reviewed. The current adapter handles one explicit subscription per invocation.

Every response includes provider, subscription, operation window, pages, record count, truncation, partial failures, completeness for that operation and required permission actions. A partial response must not be interpreted as a complete subscription security inventory. The SDK has built-in transient retry handling; final errors are retained as partial failures where prior pages were already retrieved.

No live Azure calls were made as part of this code change. Azure credentials, account ownership, subscription policy and actual API behavior still need validation in an approved subscription. Read-only is not a guarantee of zero provider-side cost or zero API throttling.
