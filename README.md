# NovaTech Zero Trust Lab

A demo company ("NovaTech") protected with a zero trust architecture:
nobody is trusted by default, every request is verified.

## Phase 1 (this commit): identity + isolated apps

```
Browser -> hr-proxy / finance-proxy  -> Keycloak (login + MFA + roles)
              |                              
              v (only if role matches)
          hr-app / finance-app   (each on its own internal network, no internet)
```

Zero trust ideas already in place:
- **Verify explicitly**: every request goes through an identity-aware proxy
- **MFA**: users must enrol an authenticator app on first login
- **Least privilege**: HR role -> HR app only, Finance role -> Finance app only
- **Micro-segmentation**: apps live on `internal` Docker networks, unreachable except through their proxy
- **Short-lived access**: 5 min tokens, 15 min idle session timeout, brute-force lockout

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
   Wait about 60 seconds for Keycloak to start. Proxies restart on their own until Keycloak is ready.

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
1. Open the HR app, log in as `priya`, scan the QR code with Google Authenticator, enter the code -> HR page shows.
2. In the same browser open the Finance app -> **403 Forbidden** (priya has no finance role). That's least privilege.
3. Log in as `rahul` in a private window -> Finance works, HR is denied.

## Check isolation
```
docker compose exec hr-app python -c "import urllib.request;urllib.request.urlopen('http://finance-app:8000',timeout=3)"
```
This should fail: the HR app cannot reach the Finance app.

## Roadmap
- [x] Phase 1: Keycloak, MFA, role-based access, isolated networks
- [ ] Phase 2: OPA policy engine (default deny, Rego rules)
- [ ] Phase 3: phishing simulation (GoPhish) + trust score service
- [ ] Phase 4: mTLS, logging dashboard
- [ ] Phase 5: attack demos (flat network vs zero trust) and report

> Lab-only credentials. Do not deploy this as-is.
