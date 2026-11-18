# Attack-path correlation model (offline)

CloudShield's incident attack-path view is an explainable correlation graph, not a causal attack-path solver.

## Model v2

The graph is built only from the incident timeline and includes:
- Incident-level actor and account attribution nodes.
- Event/finding nodes and referenced resource nodes.
- Explicit event-to-actor, event-to-account and event-to-resource context edges.
- Adjacent-event sequence hypotheses only when there is a concrete correlation signal: a shared resource, matching non-empty event actor fields, or incident-level actor attribution.
- A maximum temporal gap of 24 hours when both timestamps are valid. Invalid/missing timestamps do not create a temporal confidence claim; gaps above the limit suppress sequence edges.
- Duplicate event identifiers are disambiguated in the graph so edge references remain unique.

Each sequence edge includes its evidence reasons, shared resources, time gap (when calculable), a conservative confidence label, and `causal: false`.

## What it does not claim

It does not infer IAM privilege reachability, network paths, exploitable trust relationships, lateral movement, or causality. Incident-level actor attribution is weaker than matching actor fields on both events. A shared actor/resource is correlation, not proof. The graph is incomplete by design and should be reviewed alongside source events and evidence.

A future causal attack-path engine requires authoritative identity relationships, effective permissions, network topology, resource policies, trust policies and time-aligned configuration snapshots. Those inputs are not available from the current event-only dataset.