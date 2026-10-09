# Known limitations

- The firewall event is a button-driven simulation. The lab does not inspect a real endpoint's firewall, antivirus, encryption, or patch level.
- The risk score is kept in memory and is keyed by username, not a cryptographically identified device. Restarting `risk-engine` resets scores.
- The fake Finance balance and transaction list are in memory and reset when `finance-app` restarts. No real payment is sent.
- The audit history is SQLite-backed and persists in the `audit-data` Docker volume. The app displays only the signed-in user's latest events.
- The attacker demo has no authenticated session. It demonstrates authentication gates and network isolation, not phishing, stolen-token replay, or MFA bypass.
- The lab uses development-mode Keycloak, local HTTP, test credentials, and static demo client secrets. It is for a local coursework lab and is not safe for production deployment.
- The project does not yet use mutual TLS, hardware-backed device keys, a real device-management platform, or a separate persistent event dashboard.

These limits are deliberate scope boundaries for the current prototype. State them in the report and distinguish simulated signals from measured endpoint data.
