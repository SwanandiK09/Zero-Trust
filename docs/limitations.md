# Known limitations

- The Windows posture script reads the three local Windows Firewall profile states. It does not inspect antivirus, encryption, patch level, or prove that the report came from a hardware-backed device. The optional negative-test flag sends an explicitly synthetic firewall-off value; it does not alter the host firewall.
- The risk score is kept in memory and is keyed by username, not a cryptographically identified device. Restarting `risk-engine` resets scores. The local agent and service share a lab HMAC secret, not a per-device certificate.
- The fake Finance balance and transaction list are in memory and reset when `finance-app` restarts. No real payment is sent.
- The audit history is SQLite-backed and persists in the `audit-data` Docker volume. The app displays only the signed-in user's latest events.
- The attacker demo has no authenticated session. It demonstrates authentication gates and network isolation, not phishing, stolen-token replay, or MFA bypass.
- The lab uses development-mode Keycloak, locally trusted lab certificates, test credentials, and static demo client secrets. It is for a local coursework lab and is not safe for production deployment.
- Device certificates are file-backed lab keys, not TPM-protected hardware keys. The CA issues certs but there is no automated revocation/CRL flow yet; rotate the lab CA to invalidate all issued devices.
- mTLS proves possession of a certificate at the gateway, but OAuth tokens are not cryptographically bound to that certificate. A stolen token used from another enrolled device is not separately detected.
- The project does not use a real device-management platform or a separate persistent event dashboard.

These limits are deliberate scope boundaries for the current prototype. State them in the report and distinguish simulated signals from measured endpoint data.
