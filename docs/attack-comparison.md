# Demo evaluation runbook

This runbook records what the lab can demonstrate today. It does not claim to measure an unsecured production baseline. Run only against this local lab and use the test accounts.

## Test cases

| Scenario | How to perform it | Expected result | Evidence to save |
|---|---|---|---|
| Correct role, normal score | Sign in as `rahul` at Finance with score 100, then make a small demo transfer. | OPA allows the request; fake balance and recent activity update. | Finance page and audit row for `transfer / allow`. |
| Wrong department role | Sign out, sign in as `priya`, and open Finance. | OPA denies access because Priya has the HR role. | Denial page or app response and the matching audit row if the app receives the request. |
| Outsider without a session | Run `docker compose --profile attack run --rm attacker`. | The proxy redirects the request to sign-in; direct backend names do not resolve on the attacker's network. | Terminal output from the attacker container. |
| Real Windows Firewall posture | Sign in as `rahul` before reporting; then run `powershell -ExecutionPolicy Bypass -File .\posture-agent\report.ps1 -User rahul` and reload Finance. | Unreported posture is denied. A report with all three firewall profiles enabled sets score 100 and allows the next request. | Security panel with device name and score; posture signal and allow audit rows. |
| Risk changes during a session | Run `powershell -ExecutionPolicy Bypass -File .\posture-agent\report.ps1 -User rahul -SimulateFirewallDisabled`, then try a transfer without signing out. | A marked lab-only synthetic signal lowers score to 20; OPA denies the transfer. The fake balance does not change. Run the script without the flag to restore the actual state. | Denial page and audit rows for the posture signal and denied transfer. |

## Record your results

| Scenario | Observed outcome | Screenshot or log filename | Notes |
|---|---|---|---|
| Correct role, normal score | Fill in after running |  |  |
| Wrong department role | Fill in after running |  |  |
| Outsider without a session | Fill in after running |  |  |
| Real Windows Firewall posture | Fill in after running |  |  |
| Risk changes during a session | Fill in after running |  |  |

The `attacker` container tests an outsider without a valid session and checks network reachability. It does not simulate stolen credentials, token theft, or a flat-network baseline.
