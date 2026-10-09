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
   Wait about 60 seconds for Keycloak to start. Proxies restart on their own until Keycloak is ready. OPA starts with the stack and is only reachable by the protected apps.

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

## Phase 3: interactive risk and payment demo

The Finance app is a fake banking dashboard with a balance, recent activity, a transfer form, and a device security panel. Transfers update an in-memory demo ledger only; no real payment is sent. Before each page view or transfer, the app asks OPA using the user's Keycloak roles and the current score from the risk service. OPA allows the action only when the user has the Finance role and the score is at least 60.

To demo the effect:

1. Update the containers in this folder without removing Keycloak's saved data:

   ```sh
   docker compose up -d --build
   ```

2. Sign in as `rahul` at the Finance app. The dashboard should show a score of `100/100` and a demo balance.
3. Make a small mock transfer. The app checks the request with OPA, reduces the demo balance, and adds it to Recent activity.
4. In the security panel, submit **Simulate firewall being disabled**. The risk service records the device as non-compliant and lowers Rahul's score to `20/100`.
5. On the result page, enter another mock transfer and submit it. OPA denies the transfer because the score is below 60; the balance and activity list stay unchanged.
6. To reset the risk score and fake ledger for another run, use:

   ```sh
   docker compose restart risk-engine finance-app
   ```

The risk score and ledger are stored in memory for this local demo. Restarting those two services resets the demo data without resetting Keycloak or MFA. Avoid `docker compose down` for ordinary restarts.

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

## Roadmap
- [x] Phase 1: Keycloak, MFA, role-based access, isolated networks
- [x] Phase 1b: attacker container (no-session + segmentation demo)
- [x] Phase 2: OPA policy engine (default deny, Rego rules, app asks OPA on each request)
- [x] Phase 3: simulated unsafe-device signal + in-memory trust score + OPA re-check on the next request
- [ ] Phase 4: phishing simulation (GoPhish), mTLS, and logging dashboard
- [ ] Phase 5: attack demos (flat network vs zero trust) and report

> Lab-only credentials. Do not deploy this as-is.
