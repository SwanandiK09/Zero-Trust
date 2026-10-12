# NovaTech Zero Trust Lab

A lab-only demo company protected with a Zero Trust architecture. The principle is simple: nobody is trusted by default, and access is evaluated using identity, roles, device posture, and risk.

## Architecture

```text
Browser
   |
   v
HR / Finance proxy
   |
   +----> Keycloak (login and MFA)
   |
   v
HR / Finance application
   |
   +----> Risk engine (current risk score)
   |
   +----> OPA (authorization decision)
   |
   +----> Audit log (policy decisions)

Certificate setup and device posture scripts
support additional device-trust demonstrations.
```

The exact entry points and enabled security controls depend on the active Docker Compose configuration. The current local demo uses HTTP proxies; do not assume mTLS gateways are enabled unless the Compose configuration has been updated for them.

## Zero Trust controls

- **Verify explicitly:** Users authenticate through identity-aware proxies.
- **Multi-factor authentication:** Keycloak supports authenticator-app MFA.
- **Least privilege:** OPA checks the user's roles against the requested resource.
- **Micro-segmentation:** Internal Docker networks restrict communication between services.
- **Short-lived access:** The lab configures token/session timeouts and brute-force protection.
- **Separate policy engine:** Applications ask OPA for authorization decisions.
- **Changing risk:** The risk engine supplies the current trust score.
- **Device identity:** Certificate-generation scripts support device certificate enrollment. Certificate enforcement depends on the active gateway configuration.
- **Auditability:** Policy decisions can be recorded in SQLite and displayed in the applications.

## Requirements

- Docker Desktop
- PowerShell
- OpenSSL for the certificate-generation exercises

## Run the demo

From the project directory, start the services:

```sh
docker compose up -d --build
```

Check service status:

```sh
docker compose ps
```

Check the OPA policy tests:

```sh
docker compose run --rm opa test /policy -v
```

Wait for Keycloak and the application proxies to finish starting before opening the applications.

## Demo accounts

These are lab-only example credentials. Use the credentials configured in your local Keycloak realm; passwords and MFA enrollment may need to be set up locally.

| User | Intended role | Intended access |
|---|---|---|
| `priya` | `hr` | HR |
| `rahul` | `finance` | Finance |
| `imran` | `admin`, `hr`, `finance` | Both applications |

## OPA authorization

The policy is located at `opa/policy/authz.rego`.

The policy applies these checks:

1. Deny access by default.
2. Require a trust score of at least 60.
3. Require the device input to indicate a valid certificate and contain a non-empty device ID.
4. Require the role associated with the requested resource.
5. Allow the supported actions: reading resources and transferring funds in Finance, subject to the other checks.

The `device.cert_valid` field is an input to OPA. Cryptographic certificate verification must be performed by the relevant gateway or trusted upstream component; a Boolean input alone does not verify a certificate.

Tests are located at `opa/policy/authz_test.rego`. The current test run reported 12 passing tests.

OPA is intended to be accessed internally by the applications, not directly exposed as a public service.

## Risk and endpoint posture

The lab includes a risk engine and a Windows posture-agent script for reporting Windows Firewall status.

If the posture-agent files and endpoints are present in the active checkout, follow their instructions to submit a posture report and observe the resulting risk score. A simulated disabled-firewall report can be used for a negative test without changing the actual firewall configuration.

When the risk score falls below the policy threshold, protected actions should be denied. Verify the observed result in the running application and its audit logs.

## Device certificates

Certificate-related files are maintained under `pki/`, including:

- `pki/setup-ca.ps1` — create the lab certificate authority.
- `pki/issue-device.ps1` — issue a certificate for a demo device.
- `pki/device.ext` and `pki/server.ext` — certificate extension configurations.

Only run the certificate scripts after reviewing their prompts and instructions. Keep CA private keys, server private keys, device private keys, and password-protected PFX bundles out of GitHub. Generated certificates and keys should remain in the ignored generated directory unless there is a specific safe reason to publish a public certificate.

The existence of these scripts does not by itself mean the current Compose configuration enforces mutual TLS.

## Network isolation

The lab uses separate Docker networks to limit which services can communicate. Run the isolation check and attacker demo only after verifying the service names and networks in the active Compose configuration.

An attacker container should be used only against this local lab. Record actual results rather than treating expected outcomes as measured evidence.

## Evaluation and reporting

Use these documents when available:

- `docs/architecture.md` — architecture and component interactions.
- `docs/attack-comparison.md` — attack scenarios and comparison.
- `docs/limitations.md` — known limitations and scope.
- `docs/report-outline.md` — report structure.

Record test outcomes, screenshots, and limitations from your own runs.

## Roadmap

- [x] Keycloak identity and role-based access
- [x] OPA authorization policy and tests
- [x] Risk-based authorization inputs
- [x] Firewall posture and audit-log components, where configured
- [ ] Verify the complete device-certificate and mTLS path
- [ ] Add a phishing simulation and centralized logging dashboard
- [ ] Complete attack comparisons and the project report

> **Lab only:** This project is for controlled demonstrations. Do not deploy it as-is or reuse demo credentials in a real environment.