# Acceptance evidence

This directory holds machine-generated, secret-safe local verification records and screenshots captured from the running local application.

- `local-verification.json` is produced by `python scripts/capture-release-evidence.py`.
- Screenshots must be captured from the running application, reviewed for personal data and synthetic-data context, and described with their viewport and capture time.
- Never place cloud credentials, tokens, private keys, customer identifiers, unredacted audit events or personal data here.
- Local verification is not evidence of live provider acceptance, cloud write execution, production failover, off-host restore or independent security assurance.

See [Phases 28–31 acceptance package](../../docs/PHASES_28_31_ACCEPTANCE_PLAN.md) and [evidence provenance](../README.md).

## Current capture set

- local-verification.json ? six local checks on commit 01d10a97ad8d15b2b89aa2174c10993e423c5024: 188 Python tests, compileall, Bandit, the 40-case/19-rule detection evaluation, npm production audit (zero vulnerabilities) and Vite production build. No external cloud/identity/SMTP/backup calls were made.
- screenshots/08-phase-28-31-acceptance.png ? rendered release-gate diagram, captured 20 November 2026.
- SHA256SUMS.txt ? hashes for the JSON verification record and screenshot.

The phase-gate screenshot is a rendered documentation visual, not a screenshot of a live provider console. Existing product walkthrough screenshots remain under evidence/media/ and evidence/screenshots/.
