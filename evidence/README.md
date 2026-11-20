# Evidence and demonstration assets

This directory contains intentional, reviewable project evidence. It does not contain production secrets, tenant databases, raw cloud exports or local environment files.

## Included assets

| Asset | Provenance | What it demonstrates |
|---|---|---|
| media/cloudshield-demo-redacted.mp4 | Privacy-sanitized copy of the local 102-second walkthrough | Product navigation, investigation, evidence vault, alerts, response request flow, cloud connection setup and workspace administration |
| media/01-command-center-overview.png | Frame from the local walkthrough, 27 seconds | Overview metrics and event activity |
| media/02-evidence-vault.png | Frame from the local walkthrough, 48 seconds | Evidence records and integrity fingerprints |
| media/03-alerts-and-response.png | Frame from the local walkthrough, 55 seconds | HIGH/CRITICAL alert review and acknowledgement |
| media/04-guided-response-request.png | Frame from the local walkthrough, 71 seconds | Guided response request and independent-approval boundary |
| media/05-tenant-scoped-cloud-connections.png | Frame from the local walkthrough, 82 seconds | AWS AssumeRole and Azure managed/workload identity configuration |
| screenshots/sign-in-screen.png | Fresh headless capture of the local HTTPS sign-in screen | Sign-in experience without an authenticated user identity |

## Additional acceptance evidence

See [acceptance evidence](acceptance/README.md) for the local verification JSON, rendered Phase 28-31 gate visual and SHA-256 manifest. These artifacts do not replace live-provider or independent-assurance evidence.

## Privacy and data classification

The original recording contained a signed-in display name and email address in the workspace-members dialog. The public copy applies privacy redactions to the signed-in identity area throughout the video and to the member row where it appears, and crops the browser chrome. The source recording also contains an audio track; audio is intentionally omitted from the public copy because it was not separately reviewed for spoken personal or confidential information. The original recording remains in the author's Documents folder and is not committed.

The selected screenshots use the same privacy masks. The walkthrough uses a local synthetic lab dataset and example provider identifiers. It is not a recording of a live customer AWS/Azure account, production cloud containment or real provider telemetry. Do not interpret displayed counts as measured detection accuracy.

## Integrity

SHA-256 checksums are recorded in [SHA256SUMS.txt](SHA256SUMS.txt). Recompute them after any intentional evidence change. The checksums identify the committed files; they do not establish the authenticity of the original screen recording or trusted capture time.

## Review before redistribution

Review the video and screenshots before posting externally. Do not add raw browser profiles, session cookies, invitation links, authenticator QR codes, Firebase Admin SDK keys, cloud credentials, customer telemetry, tenant databases or unredacted identity information.
