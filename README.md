# NovaTech Zero Trust Lab

A demo company ("NovaTech") protected with a zero trust architecture:
nobody is trusted by default, every request is verified.

## Current demo: identity, OPA, and changing risk

```
Browser -> HR/Finance proxy -> Keycloak (login + MFA)
                 |
                 v  verified identity + roles
           Finance app -> risk score + OPA decision
                 |               |
                 +-- only run mock transfer if allowed
```

Zero trust ideas already in place:
- **Verify explicitly**: every request goes through an identity-aware proxy
- **MFA**: users must enrol an authenticator app on first login
- **Least privilege**: OPA checks the user's Keycloak roles against the requested app
- **Micro-segmentation**: apps live on `internal` Docker networks, unreachable except through their proxy
- **Short-lived access**: 5 min tokens, 15 min idle session timeout, brute-force lockout
- **Separate policy engine**: each app asks OPA for an allow/deny decision on every page request
- **Changing risk**: OPA also checks a user's current risk score on every request

## Run it

1. Install Docker Desktop and start it.
2. Add this line to your hosts file (Windows: `C:\Windows\System32\drivers\etc\hosts`, open Notepad as Administrator;
   Linux/Mac: `/etc/hosts`):
   ```
   127.0.0.1 keycloak
   ```
3. In this folder run:
   ```
   docker compose up -d --build
   ```
   Wait about 60 seconds for Keycloak to start. Proxies restart on their own until Keycloak is ready. OPA starts with the stack and is only reachable by the protected apps. The risk service's posture endpoint is published only on `127.0.0.1:8090` for the local Windows agent; its separate bridge does not join the HR or Finance app networks.

## Try it

| User | Password | Role | Should open |
|------|----------|------|-------------|
| priya | Passw0rd! | hr | HR app only |
| rahul | Passw0rd! | finance | Finance app only |
| imran | Passw0rd! | admin+hr+finance | both |

- HR app: http://localhost:4181
- Finance app: http://localhost:4182
- Keycloak admin console: http://keycloak:8080 (admin / admin)

Test script:
1. Open the HR app, log in as `priya`, scan the QR code with an authenticator app, and enter the code. The HR page appears after OPA allows it.
2. In the same browser open Finance -> **403 Forbidden**. Priya has no finance role, so OPA denies it.
3. Log in as `rahul` in a private window -> Finance works; HR is denied.
4. Log in as `imran` -> both apps work because the test account has both roles.

## Phase 2: OPA policy decisions

The proxies still handle sign-in and MFA. They pass the roles from Keycloak's verified token to the internal app. Before returning its page, the app sends OPA the username, roles, resource (`hr` or `finance`), and action (`read`). OPA applies the rules in `opa/policy/authz.rego`. The app fails closed: if OPA is unavailable, access is not granted.

Policy tests are in `opa/policy/authz_test.rego`. If you have the OPA CLI installed, run:

```sh
opa test -v opa/policy
```

OPA is not published as a host port. To inspect its decision API from an app container, use `http://opa:8181/v1/data/zerogate/authz/allow` with a JSON request containing an `input` object.

## Phase 3: endpoint firewall posture and payment demo

The Finance app is a fake banking dashboard with a balance, recent activity, a transfer form, a device security panel, and a recent access-decision table. Transfers update an in-memory demo ledger only; no real payment is sent. Before each page view or transfer, the app asks OPA using the user's Keycloak roles and the current score from the risk service. OPA allows the action only when the user has the Finance role, the action is allowed for that resource, and the score is at least 60. A small Windows PowerShell posture agent reads the actual status of all three Windows Firewall profiles and sends a signed report to the local risk service. Until it reports, access is denied (score 20); a healthy report sets the score to 100, while any disabled profile sets it to 20.

Each OPA decision is written to a SQLite audit database by the risk service. The Finance and HR pages show the signed-in user's latest decisions, including timestamp, action, resource, score, outcome, and a short reason. If the audit write fails, the app fails closed and does not perform the protected action. The audit database uses a Docker volume and survives service restarts; the demo risk scores and Finance ledger remain in memory and reset when their services restart.

To demo the effect:

1. Update the containers in this folder without removing Keycloak's saved data:

   ```sh
   docker compose up -d --build
   ```

2. Sign in as `rahul` at Finance. Before reporting posture, the app should deny access because the device has not been verified.
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
placed on the `idp-net` zone (the same zone the proxies sit on). It does
not start with the rest of the stack - run it on demand:

```
docker compose --profile attack run --rm attacker
```

It tries two things and prints whether each was blocked:
1. Requesting the HR/Finance guard directly with no session -> it is
   redirected to the Keycloak login page, never shown the app content.
2. Resolving `hr-app` / `finance-app` by name -> fails, because the
   attacker isn't on `hr-net`/`finance-net` at all (`internal: true`
   networks have no route out, and the attacker has no route in).

This demonstrates two zero trust properties: **no implicit trust from
being on the corporate network** and **micro-segmentation**. Only run
this against your own lab.

## Evaluation notes

Use [the attack comparison runbook](docs/attack-comparison.md) to perform and record the allowed-user, wrong-role, outsider, and unsafe-device scenarios. Record actual outcomes and add your own screenshots; the expected results in the runbook are not a substitute for measured results. See [known limitations](docs/limitations.md) before presenting the scope.

## Roadmap
- [x] Phase 1: Keycloak, MFA, role-based access, isolated networks
- [x] Phase 1b: attacker container (no-session + segmentation demo)
- [x] Phase 2: OPA policy engine (default deny, Rego rules, app asks OPA on each request)
- [x] Phase 3: Windows Firewall posture report + in-memory risk score + OPA re-check on the next request
- [x] Phase 3b: persistent SQLite policy-decision audit trail shown in the app
- [ ] Phase 4: phishing simulation (GoPhish), mTLS, and logging dashboard
- [ ] Phase 5: attack demos (flat network vs zero trust) and report

> Lab-only credentials. Do not deploy this as-is.
