# Phase 9 — Incident response workflow

## Features
- Persisted incident workflow states: new, acknowledged, in progress, resolved, reopened.
- Transition validation; resolved incidents must be reopened before work resumes.
- Priority P1–P4, assignee field, analyst note support.
- Append-only local activity log records creation, changes and notes, with timestamps and actor labels.
- UI controls in the incident investigation panel.

## API
- GET /api/incidents/{id}/workflow
- PATCH /api/incidents/{id}/workflow — status, assignee, priority
- POST /api/incidents/{id}/notes — note and actor

## Safety/scope
Legacy local mode uses single-user SQLite state and free-text analyst labels. Optional multi-user mode uses authenticated actors and a separate SQLite evidence database per workspace. This is not a full enterprise case-management platform. The incident detector may generate incidents deterministically from new ingested data; the workflow table stores analyst state separately and is not automatically remediated.
