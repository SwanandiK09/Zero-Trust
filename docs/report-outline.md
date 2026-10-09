# Suggested report outline

1. **Problem and objective** — explain why a successful login alone should not grant broad access.
2. **Zero Trust principles** — explain explicit verification, least privilege, and checking each request.
3. **Sample organization and assets** — describe NovaTech, HR and Finance resources, test users, and protected data (all demo data).
4. **Threat model** — list the outsider, wrong-role user, compromised session, and unsafe-device signal as lab scenarios. Explain that the Windows agent reads real firewall profile state; the disabled-state case is a clearly labeled safe synthetic test.
5. **Architecture and policy** — include `architecture.md`, the Docker network zones, and key OPA rules.
6. **Implementation** — describe Keycloak MFA, the sign-in proxies, OPA, the risk service, the audit trail, and the fake Finance action.
7. **Evaluation** — run every case in `attack-comparison.md`, report observed results, and include screenshots of the app and attacker output.
8. **Limitations** — use `limitations.md`; be clear that firewall state is simulated, and device certificates and stolen-token replay are not implemented.
9. **Conclusion and next steps** — summarize the results and propose hardware-backed device certificates, broader posture checks, or phishing-signal integration as future work.

Do not fill the results table with expected outcomes. Record what actually happened in your lab.
