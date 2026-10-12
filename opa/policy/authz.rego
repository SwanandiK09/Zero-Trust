
package zerogate.authz

import rego.v1

# Deny access unless explicitly allowed.
default allow := false

resource_roles := {
    "hr": "hr",
    "finance": "finance",
}

allow if {
    input.trust_score >= 60
    input.device.cert_valid == true
    is_string(input.device.id)
    input.device.id != ""
    required_role := resource_roles[input.resource]
    required_role in input.user.roles
    valid_action
}

valid_action if input.action == "read"

valid_action if {
    input.resource == "finance"
    input.action == "transfer"
}
