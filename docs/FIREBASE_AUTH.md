# Firebase Authentication integration

## Status and architecture

CloudShield can use Firebase Authentication for browser identity while keeping authorization, tenant membership, roles, audit history, and evidence data in its existing SQLite stores.

- The browser uses the Firebase modular Web SDK for email/password sign-in, account creation, email verification, and password-reset email.
- The backend accepts a Firebase ID token over the same-origin HTTPS API and verifies its signature, audience/project, expiry, and revocation with Firebase Admin SDK (verify_id_token with check_revoked enabled).
- A verified Firebase UID is mapped to one CloudShield user row. Workspace and role assignments remain server-side; client-supplied role claims are never trusted.
- Each workspace continues to use its own evidence database. Firebase is not used for evidence storage, Firestore, Storage, or cloud collectors.
- Existing local-password accounts are never auto-linked by matching email. They require a deliberate migration/linking procedure before changing providers.

## Firebase Console prerequisite

The Firebase project and Web app can exist before Firebase Authentication itself is initialized. In that state the Identity Toolkit API returns CONFIGURATION_NOT_FOUND, and Firebase sign-in cannot work yet.

In Firebase Console for the CloudShield project:

1. Open **Build → Authentication**.
2. Choose **Get started** to initialize Firebase Authentication.
3. Open **Sign-in method** and enable **Email/Password** (not Email link unless the UI is separately implemented).
4. Save the provider configuration.
5. Confirm the project's authorized domains include the actual CloudShield hostname and localhost for local development.
6. Review the email verification and password-reset templates, sender details, and action URL before inviting users.

Standard email/password Authentication is available on Firebase's no-cost Spark plan. Advanced MFA and enterprise SAML/OIDC sign-in require Identity Platform capabilities and may require a billing-plan upgrade. Do not upgrade billing or enable paid services without explicit approval.

**Current project check (2026-11-19):** Firebase Authentication is initialized and Email/Password is enabled for project cloudshield-ae534. The local CloudShield API reports the Firebase provider configured, the Identity Toolkit endpoint accepts the public app key (an invalid-email diagnostic returns INVALID_EMAIL rather than CONFIGURATION_NOT_FOUND), and the local auth store reports bootstrap_required=false. Live sign-in is therefore configured; actual account attempts can still fail for account-specific reasons such as an existing email, weak password, unverified address, rate limiting or an unauthorized domain.

## Environment

Set these variables in the deployment .env file. The Web SDK values are public application configuration; the Admin SDK JSON is a private server credential.

For a local Python installation (outside the supplied Docker image), install the optional server dependency with: python -m pip install -e ".[firebase]".

~~~dotenv
CLOUDSHIELD_AUTH_MODE=multi_user
CLOUDSHIELD_AUTH_PROVIDER=firebase
CLOUDSHIELD_FIREBASE_PROJECT_ID=your-project-id
CLOUDSHIELD_FIREBASE_API_KEY=your-web-api-key
CLOUDSHIELD_FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
CLOUDSHIELD_FIREBASE_APP_ID=your-web-app-id
CLOUDSHIELD_FIREBASE_MESSAGING_SENDER_ID=your-sender-id
CLOUDSHIELD_FIREBASE_CREDENTIALS_FILE=/secure/host/path/firebase-admin.json
~~~

Generate CLOUDSHIELD_BOOTSTRAP_TOKEN independently (at least 32 random ASCII characters). Never put the service-account JSON contents in .env, source code, Git, logs, or browser configuration.

The production Compose profile mounts the host key as a read-only Compose secret at /run/secrets/firebase-admin.json. The backend reads the path from CLOUDSHIELD_FIREBASE_CREDENTIALS; do not mount the credential into the frontend or Caddy. Keep the host key outside the repository and restrict its filesystem ACL to the deployment account and SYSTEM/root.

The Admin SDK identity needs only the permissions required to verify Firebase Authentication ID tokens and check user revocation. Prefer the narrow Firebase Authentication Admin role over project Owner.

## Account lifecycle

### First administrator

The first Firebase identity must have email_verified=true. If no CloudShield users exist, the backend creates the first workspace and administrator. If a bootstrap token is configured, the first-admin request must include it. Production deployments require a strong bootstrap token.

### Invited members

After the first user exists, all new identities require a valid, single-use CloudShield workspace invitation. The invitation determines the workspace and role. Firebase email addresses must be verified. Invitations continue to expire after 24 hours.

### Existing local accounts

The Firebase UID is stored in a unique firebase_uid column. The migration adds that column to existing auth databases without deleting users or changing existing password hashes. A Firebase account whose email matches an unlinked local account is rejected; it is not silently linked. Plan and audit account migration before changing an existing installation to Firebase mode.

### Sessions and revocation

After Firebase verification, CloudShield issues its own opaque, hashed, 12-hour session cookie and CSRF cookie. CloudShield's member-disable operation revokes all CloudShield sessions for that user. Firebase token revocation is checked during ID-token verification. Roles and tenant boundaries are always re-read from CloudShield's auth database.

Password reset is sent by Firebase; CloudShield never receives or stores the Firebase password. The UI returns a generic reset confirmation to reduce account enumeration.

## Compose deployment

compose.production.yaml requires CLOUDSHIELD_FIREBASE_CREDENTIALS_FILE to point to a host-side JSON key. The file is mounted read-only as a Compose secret and is not copied into the image. Keep the key in a secret manager or protected host path and rotate it if exposed.

Before deploying:
- Complete the Firebase Console prerequisite.
- Set the exact public Web app config values.
- Set the host-side Admin SDK key path and strong bootstrap token.
- Set the real domain and valid TLS email.
- Run docker compose config --quiet, build, tests, backup validation, and recovery drill.
- Deploy only behind the supplied HTTPS proxy; never publish the API port directly.

## Limits and deferred controls

- MFA (TOTP/SMS) and enterprise SAML/OIDC are not enabled by this integration. They require Identity Platform configuration/upgrade and a separate threat-model, enrollment, recovery, and test plan.
- Verified email is required for CloudShield workspace access.
- Device/session management UI, invitation email delivery, and automated existing-account linking are not included.
- Firebase Auth's email templates and authorized domains must be configured in the console.
- Public deployment, external monitoring, off-site backups, SMTP delivery, and live cloud-provider integrations still require their own credentials and infrastructure approvals.

## Troubleshooting browser authentication

The browser's Firebase SDK converts Identity Toolkit HTTP 400 responses into Firebase error codes. The HTTP status alone is not diagnostic; inspect the Firebase SDK error code rendered in the CloudShield form or the response JSON error.message in DevTools → Network → accounts:signUp.

| Firebase error | Meaning | User action |
|---|---|---|
| auth/email-already-in-use | Firebase account already exists | Switch to Sign in; use Forgot password if necessary. Do not repeatedly submit Create account. |
| auth/weak-password | Password does not meet Firebase policy | Choose a stronger password (CloudShield requires at least 12 characters for registration). |
| auth/invalid-email | Email address is malformed | Correct the email address. |
| auth/operation-not-allowed | Email/password provider is disabled | Enable Email/Password in Firebase Console. |
| auth/unauthorized-domain | Current hostname is not authorized | Add the exact hostname in Authentication → Settings → Authorized domains. |
| auth/too-many-requests | Firebase rate limiting | Wait before retrying; do not automate repeated attempts. |
| auth/network-request-failed | Browser could not reach Firebase | Check connectivity, DNS, proxy and privacy extensions. |
| auth/invalid-credential | Sign-in credential is not accepted | Recheck email/password; if unverified, sign in to trigger another verification email. |

A GET /api/auth/me response of 401 before a CloudShield session is issued is expected. After a successful Firebase sign-in, CloudShield verifies the Firebase ID token and creates its own session cookie; subsequent /api/auth/me requests should return the CloudShield user. A Firebase account existing by itself does not yet imply that a CloudShield workspace membership has been created.


## TOTP MFA and organization SSO (Phase 21)

The web client supports Firebase TOTP second-factor enrollment and sign-in challenges. Users can open **Account security** to enroll an authenticator using a manual setup secret or copied otpauth URI, add a second device, and remove a factor when another factor remains. Sign-in resolves Firebase's `auth/multi-factor-auth-required` challenge with a six-digit TOTP code.

Before enforcing MFA, enable Firebase Authentication with Identity Platform, enable TOTP as a second factor, enroll users from Account security and test a fresh sign-in. This client does not implement SMS MFA or recovery codes; do not enforce TOTP until the user recovery process is ready.

Firebase OIDC/SAML SSO is enabled by configuring one provider in Firebase and setting `CLOUDSHIELD_FIREBASE_SSO_PROVIDER_ID` to its Firebase provider ID (for example `oidc.company` or `saml.company`) in the private server environment. The sign-in screen then shows **Continue with organization SSO**. Configure authorized domains, provider metadata and verified-email claims in Firebase before enabling it.
