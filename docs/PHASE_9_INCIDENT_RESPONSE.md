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
Single-user local SQLite state. Analyst actor is a free-text label, not authentication. This is not a shared team case-management system. The incident detector may generate incidents deterministically from new ingested data; the workflow table stores analyst state separately and is not automatically remediated.
