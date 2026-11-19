import unittest
from datetime import datetime, timezone
from types import SimpleNamespace

from cloudshield.azure_provider import collect_inventory, collect_activity_logs
from cloudshield.events import load_events
from cloudshield.detector import analyze_event

SUBSCRIPTION = "12345678-1234-4234-8234-123456789abc"

class Paged:
    def __init__(self, pages, token=None): self.pages, self.token = pages, token
    def by_page(self):
        owner = self
        class Iterator:
            def __init__(self): self.index = 0
            @property
            def continuation_token(self): return owner.token if self.index >= len(owner.pages) else None
            def __iter__(self): return self
            def __next__(self):
                if self.index >= len(owner.pages): raise StopIteration
                page = owner.pages[self.index]; self.index += 1
                if isinstance(page, Exception): raise page
                return iter(page)
        return Iterator()

class AzureResourceClient:
    def __init__(self, paged): self.paged = paged; self.calls = 0
    class Resources:
        def __init__(self, owner): self.owner = owner
        def list(self): self.owner.calls += 1; return self.owner.paged
    @property
    def resources(self): return self.Resources(self)

class AzureMonitorClient:
    def __init__(self, paged): self.paged = paged; self.filter = None
    class ActivityLogs:
        def __init__(self, owner): self.owner = owner
        def list(self, **kwargs): self.owner.filter = kwargs["filter"]; return self.owner.paged
    @property
    def activity_logs(self): return self.ActivityLogs(self)

class AzureProviderTests(unittest.TestCase):
    def test_inventory_is_read_only_and_reports_bounded_scope(self):
        client = AzureResourceClient(Paged([[SimpleNamespace(id="/subscriptions/"+SUBSCRIPTION+"/resourceGroups/lab/providers/Microsoft.Compute/virtualMachines/vm1", name="vm1", type="Microsoft.Compute/virtualMachines", location="westeurope", tags={"env":"lab"})]]))
        result = collect_inventory(SUBSCRIPTION, resource_client=client)
        self.assertEqual("azure", result["provider"])
        self.assertEqual(1, result["resource_count"])
        self.assertEqual("lab", result["resources"][0]["resource_group"])
        self.assertTrue(result["complete"])
        self.assertEqual(1, client.calls)

    def test_inventory_page_limit_is_explicitly_truncated(self):
        client = AzureResourceClient(Paged([[1], [2]], token="continuation"))
        result = collect_inventory(SUBSCRIPTION, max_pages=1, resource_client=client)
        self.assertTrue(result["truncated"])
        self.assertFalse(result["complete"])

    def test_partial_page_failure_preserves_collected_resources(self):
        client = AzureResourceClient(Paged([[SimpleNamespace(id="/subscriptions/"+SUBSCRIPTION+"/resourceGroups/lab/providers/Microsoft.Storage/storageAccounts/a", name="a", type="Microsoft.Storage/storageAccounts", location="eastus")], RuntimeError("forbidden")]))
        result = collect_inventory(SUBSCRIPTION, resource_client=client)
        self.assertEqual(1, result["resource_count"])
        self.assertFalse(result["complete"])
        self.assertEqual("RuntimeError", result["partial_failures"][0]["type"])

    def test_activity_logs_normalize_and_detect_rbac_change(self):
        item = SimpleNamespace(
            event_data_id="evt-1", operation_name=SimpleNamespace(value="Microsoft.Authorization/roleAssignments/write"),
            event_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), caller="alice@example.test",
            resource_id="/subscriptions/"+SUBSCRIPTION+"/providers/Microsoft.Authorization/roleAssignments/abc",
            resource_location="global", category=SimpleNamespace(value="Administrative"),
            status=SimpleNamespace(value="Succeeded"), authorization={"action":"Microsoft.Authorization/roleAssignments/write"},
            http_request=SimpleNamespace(client_ip_address="192.0.2.1"), properties={})
        monitor = AzureMonitorClient(Paged([[item]]))
        result = collect_activity_logs(SUBSCRIPTION, monitor_client=monitor)
        self.assertIn("eventTimestamp ge", monitor.filter)
        self.assertEqual("azure_activity_log", load_events(result["events"])[0].source_format)
        findings = analyze_event(load_events(result["events"])[0])
        self.assertEqual("CS-AZ-IAM-001", findings[0].rule_id)

    def test_diagnostic_settings_deletion_detected(self):
        row = {"eventSource":"azure.activitylogs","eventName":"Microsoft.Insights/diagnosticSettings/delete","recipientAccountId":SUBSCRIPTION}
        self.assertIn("CS-AZ-AUDIT-001", {f.rule_id for f in analyze_event(load_events(row)[0])})

    def test_validation_rejects_invalid_scope_and_bounds(self):
        with self.assertRaises(ValueError): collect_inventory("not-a-subscription", resource_client=AzureResourceClient(Paged([])))
        with self.assertRaises(ValueError): collect_activity_logs(SUBSCRIPTION, lookback_hours=169, monitor_client=AzureMonitorClient(Paged([])))
        with self.assertRaises(ValueError): collect_inventory(SUBSCRIPTION, max_pages=21, resource_client=AzureResourceClient(Paged([])))

if __name__ == "__main__": unittest.main()
