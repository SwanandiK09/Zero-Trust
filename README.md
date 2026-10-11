# NovaTech Zero Trust Lab

A demo company ("NovaTech") protected with a zero trust architecture:
nobody is trusted by default, every request is verified.

## Current demo: identity, OPA, and changing risk

```
Browser + device certificate -> Caddy HTTPS gateway (mTLS)
                                      |
                           oauth2-proxy -> Keycloak (login + MFA)
                                      |
                         App -> risk score + OPA decision
                                      |
                         mock action only if allowed
```

Zero trust ideas already in place:
- **Verify explicitly**: every request goes through an identity-aware proxy
- **MFA**: users must enrol an authenticator app on first login
- **Least privilege**: OPA checks the user's Keycloak roles against the requested app
- **Micro-segmentation**: apps live on `internal` Docker networks, unreachable except through their proxy
- **Short-lived access**: 5 min tokens, 15 min idle session timeout, brute-force lockout
- **Separate policy engine**: each app asks OPA for an allow/deny decision on every page request
- **Changing risk**: OPA also checks a user's current risk score on every request
- **Device identity**: Caddy gateways require a client certificate signed by the lab CA; OPA receives its fingerprint on each request

## Run it

1. Install Docker Desktop and start it.
2. Add this line to your hosts file (Windows: `C:\Windows\System32\drivers\etc\hosts`, open Notepad as Administrator;
   Linux/Mac: `/etc/hosts`):
   ```
   127.0.0.1 keycloak
   ```
3. Install OpenSSL for Windows, then create the lab CA and HTTPS server certificate. OpenSSL prompts for a passphrase to protect the CA key; keep it safe because you need it to issue more device certificates:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\pki\setup-ca.ps1
   ```
4. Issue a certificate for each demo device. OpenSSL asks for the CA passphrase and a PFX password; the script deletes the temporary unencrypted device key after exporting the password-protected PFX:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\pki\issue-device.ps1 -DeviceId rahul-laptop
   ```
   Import the CA certificate into the current Windows user's trusted roots, and the PFX into the user's Personal certificate store:
   ```powershell
   Import-Certificate -FilePath .\pki\generated\ca.crt -CertStoreLocation Cert:\CurrentUser\Root
   $pfxPassword = Read-Host 'PFX password' -AsSecureString
   Import-PfxCertificate -FilePath .\pki\generated\devices\rahul-laptop.pfx -CertStoreLocation Cert:\CurrentUser\My -Password $pfxPassword
   ```
   Repeat the issue/import steps for each enrolled device, using a different device ID and PFX.
5. Start the project:
   ```
   docker compose up -d --build
   ```
   If this is an existing Keycloak install, first update the two OAuth client redirect URIs as described below; this preserves your users and MFA setup. Do not run `docker compose down -v`. Wait about 60 seconds for Keycloak to start. Caddy accepts HTTPS only when the browser presents a valid device certificate. Its HR and Finance gateways have separate networks and are published only on `127.0.0.1`. The risk service's posture endpoint is also local-only on `127.0.0.1:8090`.

## Try it

| User | Password | Role | Should open |
|------|----------|------|-------------|
| priya | Passw0rd! | hr | HR app only |
| rahul | Passw0rd! | finance | Finance app only |
| imran | Passw0rd! | admin+hr+finance | both |

- HR app: https://localhost:4181
- Finance app: https://localhost:4182
- Keycloak admin console: http://keycloak:8080 (admin / admin)

Test script:
1. Open the Finance app in Chrome or Edge. When prompted, choose the enrolled device certificate. Then sign in as `rahul`, scan the QR code with an authenticator app, and enter the code. The Finance page appears after OPA allows it.
2. In the same browser open HR as `rahul` -> access is denied because Rahul has no HR role.
3. Sign out and log in as `priya` -> HR works; Finance is denied because Priya has no Finance role.
4. Log in as `imran` -> both apps work because the test account has both roles.

## Phase 2: OPA policy decisions

The proxies still handle sign-in and MFA. They pass the roles from Keycloak's verified token to the internal app. Before returning its page, the app sends OPA the username, roles, resource (`hr` or `finance`), action, verified device-certificate fingerprint, and risk score. OPA applies the rules in `opa/policy/authz.rego`. The app fails closed: if OPA is unavailable, access is not granted.

## Device certificates and mutual TLS

The lab CA issues a unique client certificate to each enrolled device. The browser presents that certificate to the Caddy gateway during the HTTPS connection, and Caddy verifies that it chains to the lab CA. Requests without a trusted certificate are rejected at the gateway. Caddy forwards the verified certificate fingerprint to the app, and OPA requires a valid certificate along with the correct role and score. The CA private key, server key, device keys, certificates, and PFX files are under `pki/generated/` and are ignored by Git.

For an existing Keycloak installation, open `http://keycloak:8080` and sign in to the admin console. In the `novatech` realm, open Clients → `hr-app` and set its Valid Redirect URIs to `https://localhost:4181/oauth2/callback`; do the same for `finance-app` with `https://localhost:4182/oauth2/callback`. The realm import file contains these URLs for a fresh install. This keeps existing users and MFA enrollment intact.

Policy tests are in `opa/policy/authz_test.rego`. If you have the OPA CLI installed, run:

```sh
opa test -v opa/policy
```

OPA is not published as a host port. To inspect its decision API from an app container, use `http://opa:8181/v1/data/zerogate/authz/allow` with a JSON request containing an `input` object.

## Endpoint firewall posture and payment demo

The Finance app is a fake banking dashboard with a balance, recent activity, a transfer form, a device security panel, and a recent access-decision table. Transfers update an in-memory demo ledger only; no real payment is sent. Before each page view or transfer, the app asks OPA using the user's Keycloak roles and the current score from the risk service. OPA allows the action only when the user has the Finance role, the action is allowed for that resource, and the score is at least 60. A small Windows PowerShell posture agent reads the actual status of all three Windows Firewall profiles and sends a signed report to the local risk service. Until it reports, access is denied (score 20); a healthy report sets the score to 100, while any disabled profile sets it to 20.

Each OPA decision is written to a SQLite audit database by the risk service. The Finance and HR pages show the signed-in user's latest decisions, including timestamp, action, resource, score, outcome, and a short reason. If the audit write fails, the app fails closed and does not perform the protected action. The audit database uses a Docker volume and survives service restarts; the demo risk scores and Finance ledger remain in memory and reset when their services restart.

To demo the effect:

1. Update the containers in this folder without removing Keycloak's saved data:

   ```sh
   docker compose up -d --build
   ```

2. Open `https://localhost:4182`, choose the device certificate when prompted, and sign in as `rahul`. Before reporting posture, the app should deny access because firewall health has not yet been reported.
3. In a separate PowerShell window, from this project folder run `powershell -ExecutionPolicy Bypass -File .\posture-agent\report.ps1 -User rahul`. The script checks Windows Firewall and reports the computer name. It does not change firewall settings. Reload Finance; with all firewall profiles enabled, the score should be `100/100`.
4. Make a small mock transfer. OPA checks the role and current score, then the app updates its fake balance and activity.
5. For a safe negative test, run `powershell -ExecutionPolicy Bypass -File .\posture-agent\report.ps1 -User rahul -SimulateFirewallDisabled`. This sends a clearly marked synthetic disabled signal without changing the real firewall. Reload Finance and try a transfer: OPA should deny it at score `20/100`, with no ledger change.
6. Run the script again without `-SimulateFirewallDisabled` to report the real state and restore the score. The dashboard and denied page show the audit trail. To reset the in-memory risk score and fake ledger for another run, use:

   ```sh
   docker compose restart risk-engine finance-app
   ```

Restarting those two services resets the risk score and ledger without resetting Keycloak, MFA, or the audit history. Avoid `docker compose down -v` unless you intend to remove persistent Docker data.

## Check isolation
```
docker compose exec hr-app python -c "import urllib.request;urllib.request.urlopen('http://finance-app:8000',timeout=3)"
```
This should fail: the HR app cannot reach the Finance app.

## Attacker demo (lab-only)

A small container that plays an outsider with **no valid login session**,
placed on a separate, isolated `attack-net`. It does not start with the rest
of the stack - run it on demand:

```
docker compose --profile attack run --rm attacker
```

It tries direct connections to the HR/Finance sign-in proxies and app
containers. They should fail because the attacker has no route to `idp-net`,
`hr-net`, or `finance-net`. The only host-published app entry points are the
local HTTPS gateways, which require a valid device certificate.

This demonstrates **network isolation**. The certificate test in the runbook
demonstrates that an untrusted device is rejected at the HTTPS gateway. Only
run this against your own lab.

## Evaluation notes

Use [the attack comparison runbook](docs/attack-comparison.md) to perform and record the allowed-user, wrong-role, outsider, and unsafe-device scenarios. Record actual outcomes and add your own screenshots; the expected results in the runbook are not a substitute for measured results. See [known limitations](docs/limitations.md) before presenting the scope.

## Roadmap
- [x] Phase 1: Keycloak, MFA, role-based access, isolated networks
- [x] Phase 1b: attacker container (no-session + segmentation demo)
- [x] Phase 2: OPA policy engine (default deny, Rego rules, app asks OPA on each request)
- [x] Phase 3: Windows Firewall posture report + in-memory risk score + OPA re-check on the next request
- [x] Phase 3b: persistent SQLite policy-decision audit trail shown in the app
- [x] Phase 4: lab CA, device certificates, HTTPS gateways with mTLS, and OPA certificate checks
- [ ] Phase 5: phishing simulation (GoPhish) and logging dashboard
- [ ] Phase 5: attack demos (flat network vs zero trust) and report

> Lab-only credentials. Do not deploy this as-is.
