# Project screenshots and evidence

This directory contains screenshots and verification records for the CloudShield application. It does not contain production secrets, tenant databases, raw cloud exports or local environment files.

## Included assets

| Asset | Provenance | What it demonstrates |
|---|---|---|
| media/01-command-center-overview.png | Application screenshot | Overview metrics and event activity |
| media/02-evidence-vault.png | Application screenshot | Evidence records and integrity fingerprints |
| media/03-alerts-and-response.png | Application screenshot | HIGH/CRITICAL alert review and acknowledgement |
| media/04-guided-response-request.png | Application screenshot | Guided response request and independent-approval boundary |
| media/05-tenant-scoped-cloud-connections.png | Application screenshot | AWS AssumeRole and Azure managed/workload identity configuration |
| screenshots/sign-in-screen.png | Fresh headless capture of the local HTTPS sign-in screen | Sign-in experience without an authenticated user identity |

## Additional acceptance evidence

See [acceptance evidence](acceptance/README.md) for the local verification JSON, rendered Phase 28-31 gate visual and SHA-256 manifest. These artifacts do not replace live-provider or independent-assurance evidence.

The screenshots show the local application with synthetic lab data and example provider identifiers. They do not represent live customer AWS/Azure telemetry or production cloud containment. Displayed counts are illustrative and are not detection-accuracy measurements.

## Integrity

SHA-256 checksums are recorded in [SHA256SUMS.txt](SHA256SUMS.txt). Recompute them after any intentional evidence change. The checksums identify the committed files; they do not establish the authenticity of the original screen recording or trusted capture time.

## Review before redistribution

Review the video and screenshots before posting externally. Do not add raw browser profiles, session cookies, invitation links, authenticator QR codes, Firebase Admin SDK keys, cloud credentials, customer telemetry, tenant databases or unredacted identity information.
