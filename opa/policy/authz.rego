package zerogate.authz

import rego.v1

# A request is denied unless a rule below explicitly allows it.
default allow := false

resource_roles := {
    "hr": "hr",
    "finance": "finance",
}

allow if {
    input.trust_score >= 60
    required_role := resource_roles[input.resource]
    required_role in input.user.roles
    valid_action
}

valid_action if input.action == "read"

valid_action if {
    input.resource == "finance"
    input.action in {"transfer", "simulate_device_issue"}
}
