# Architecture

```mermaid
flowchart LR
    B[Employee browser] --> P[HR or Finance sign-in proxy]
    P -->|sign in and MFA| K[Keycloak]
    P -->|identity and roles| A[HR or Finance app]
    A -->|user role, resource, action, risk score| O[OPA policy engine]
    A -->|read score / write decision| R[Risk service]
    R --> DB[(SQLite audit volume)]
    A -->|allowed request| D[Protected demo page or fake transfer]
    X[Optional attacker container] -->|no session| P
    X -. no route .-> A
```

Each protected app and its proxy share a department network. The proxies also share the identity network with Keycloak. OPA and the risk service attach to the HR and Finance networks so both apps can request policy decisions and risk scores. The apps themselves do not share a network.

For each app request, the app asks OPA whether the user role, requested action, resource, and current risk score satisfy policy. The app records the decision in the risk service's SQLite database before it returns the page or performs a fake transfer. A failed audit write blocks the protected action.

The attacker container is an outsider test. It can reach the sign-in proxies without having a session, but it is not connected to the internal HR or Finance networks.
