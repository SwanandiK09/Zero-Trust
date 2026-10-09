# Demo evaluation runbook

This runbook records what the lab can demonstrate today. It does not claim to measure an unsecured production baseline. Run only against this local lab and use the test accounts.

## Test cases

| Scenario | How to perform it | Expected result | Evidence to save |
|---|---|---|---|
| Correct role, normal score | Sign in as `rahul` at Finance with score 100, then make a small demo transfer. | OPA allows the request; fake balance and recent activity update. | Finance page and audit row for `transfer / allow`. |
| Wrong department role | Sign out, sign in as `priya`, and open Finance. | OPA denies access because Priya has the HR role. | Denial page or app response and the matching audit row if the app receives the request. |
| Outsider without a session | Run `docker compose --profile attack run --rm attacker`. | The proxy redirects the request to sign-in; direct backend names do not resolve on the attacker's network. | Terminal output from the attacker container. |
| Risk changes during a session | As `rahul`, submit **Simulate firewall being disabled**, then try another transfer without signing out. | The score falls from 100 to 20; OPA denies the next transfer. The fake balance does not change. | Denial page and audit rows for the signal and denied transfer. |

## Record your results

| Scenario | Observed outcome | Screenshot or log filename | Notes |
|---|---|---|---|
| Correct role, normal score | Fill in after running |  |  |
| Wrong department role | Fill in after running |  |  |
| Outsider without a session | Fill in after running |  |  |
| Risk changes during a session | Fill in after running |  |  |

The `attacker` container tests an outsider without a valid session and checks network reachability. It does not simulate stolen credentials, token theft, or a flat-network baseline.
