# Firebase identity phase — completion report

**Date:** 19 November 2026  
**Repository:** TheRootBaba/CloudShield-Lab  
**Branch:** feat/firebase-auth-integration

## Executive summary

The application-side Firebase Authentication integration, local production profile, secret mounting, documentation, and regression coverage are implemented. The rebuilt local Docker stack is healthy and remains bound to loopback-only host ports. Firebase Authentication itself is the remaining blocker: the Firebase project has not yet initialized the Authentication product, and Google's Identity Toolkit API returns CONFIGURATION_NOT_FOUND. No billing upgrade or paid Firebase service was enabled.

## Delivered

- Firebase Web SDK email/password registration and sign-in, email verification, and password-reset flow in the branded UI.
- Backend Firebase Admin ID-token verification, project binding, token revocation check, verified-email enforcement, and CloudShield session issuance.
- Unique Firebase UID mapping in the existing auth database; role and tenant authorization remain server-side in CloudShield.
- Single-use invitations, first-admin bootstrap, workspace isolation, and disabled-member checks are preserved.
- Existing local-password accounts are not silently linked by email.
- Firebase mode blocks legacy password login/registration endpoints.
- Public Firebase Web app settings are environment-driven; Admin SDK JSON is mounted read-only as a Docker secret and kept outside the repository.
- Dedicated identity-egress network for Google Auth/certificate calls; production host firewall must restrict outbound traffic to required Google endpoints.
- Firebase integration guide and updates to multi-user and finalization documentation.
- The known synthetic recovery-test account was removed from the local Docker volume after verifying it was the only account and its workspace contained no evidence. First-admin bootstrap is now required again.

## Validation

| Check | Result |
|---|---|
| Python test suite | 147 passed; 42 subtests passed |
| Auth + recovery statement coverage | 95% combined (auth 97%, recovery 92%) |
| Python compileall | Passed |
| Bandit source scan | Passed; no findings |
| Git diff whitespace check | Passed |
| Vite production build | Passed; warning remains for a JavaScript chunk over 500 kB |
| npm production dependency audit | 0 vulnerabilities |
| Production dependency lock | 51 pinned Python packages; Docker image build succeeded |
| Production Compose config | Passed |
| Docker image | Built successfully |
| Local Docker app health | HTTP 200 |
| Local UI root | HTTP 200 |
| Auth config endpoint | Firebase provider enabled and public config present |
| Firebase Admin secret | Mounted read-only at /run/secrets/firebase-admin.json; project ID checked without exposing key material |
| Google certificate endpoint from app container | HTTP 200 |
| Container posture | Non-root 10001:10001, read-only root filesystem, all Linux capabilities dropped, no host API port binding |
| Local ingress | Caddy loopback-only host ports 8088 and 8443 |
| Firebase Auth live sign-in | Blocked: Authentication config not initialized |
| Python pip-audit | No local result; the audit process did not complete. CI now installs the Firebase extra and audits both installed project dependencies and requirements-cloud.lock. Treat Python dependencies as pending until that CI audit completes. |

## Firebase project and key status

- Project ID: cloudshield-ae534.
- The actual CloudShield Web app was re-read from Firebase CLI; all five public SDK settings (API key, auth domain, project ID, app ID, sender ID) match the ignored local deployment environment file.
- Admin SDK key is stored outside the repository at C:\Users\hp\.config\cloudshield\firebase-admin-cloudshield-ae534.json.
- Windows ACL was verified: inheritance removed; full access granted only to the current Windows account and SYSTEM.
- The source file in Documents is no longer present at its former location.
- The container can read the mounted secret and reach Google's public signing-certificate endpoint.
- A read-only Identity Toolkit probe and a scoped attempt to initialize Email/Password both returned CONFIGURATION_NOT_FOUND. No Firebase users were created and no provider settings were changed.

## Remaining external release gates

1. **Initialize Firebase Authentication:** in Firebase Console open Build → Authentication → Get started, then enable Email/Password and save. Add the eventual production domain to authorized domains. The local app is already configured to use Firebase and will display a clear setup error until this is done.
2. **MFA and enterprise SSO:** TOTP/SMS MFA and SAML/OIDC are not enabled. These require Identity Platform capabilities and may require a paid-plan upgrade; no upgrade was made.
3. **Production domain and host:** no approved domain, DNS, VPS/host, firewall policy, or production owner is available. Public ACME TLS and deployment remain unperformed.
4. **Outbound egress policy:** restrict the app's identity-egress network at the production host firewall to the required Firebase/Google Auth and signing-certificate endpoints.
5. **Cloud providers:** AWS and Oracle credentials/accounts are not available; Azure credentials are not configured. Provider collection remains disabled.
6. **Operations:** external monitoring/alerting, independent off-site encrypted backups, SMTP/invitation delivery, external audit export, and an independent penetration test remain release gates.
7. **Python dependency audit:** rerun pip-audit against requirements-cloud.lock in CI or another environment where the vulnerability service responds.

## Current local state

The local Docker stack remains running and healthy. Caddy is exposed only on 127.0.0.1:8088 and 127.0.0.1:8443. The Python API is not published to the host. The local auth database is empty and reports bootstrap_required=true; do not create the first admin until Firebase Authentication has been initialized and Email/Password enabled.

## Source control

- Branch: feat/firebase-auth-integration
- Pull request: https://github.com/TheRootBaba/CloudShield-Lab/pull/12 (draft; awaiting CI and review)

No Firebase billing changes, Supabase changes, unrelated Docker service changes, or public deployments were made.
