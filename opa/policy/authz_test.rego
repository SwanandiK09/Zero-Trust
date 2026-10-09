package zerogate.authz_test

import rego.v1
import data.zerogate.authz

test_hr_role_can_read_hr if {
    authz.allow with input as {"user": {"roles": ["hr"]}, "resource": "hr", "action": "read", "trust_score": 100}
}

test_hr_role_cannot_read_finance if {
    not authz.allow with input as {"user": {"roles": ["hr"]}, "resource": "finance", "action": "read", "trust_score": 100}
}

test_finance_role_can_read_finance if {
    authz.allow with input as {"user": {"roles": ["finance"]}, "resource": "finance", "action": "read", "trust_score": 100}
}

test_admin_with_both_roles_can_read_both_resources if {
    authz.allow with input as {"user": {"roles": ["admin", "hr", "finance"]}, "resource": "finance", "action": "read", "trust_score": 100}
}

test_unknown_resource_is_denied if {
    not authz.allow with input as {"user": {"roles": ["admin"]}, "resource": "admin-panel", "action": "read", "trust_score": 100}
}

test_write_action_is_denied if {
    not authz.allow with input as {"user": {"roles": ["finance"]}, "resource": "finance", "action": "write", "trust_score": 100}
}

test_missing_roles_are_denied if {
    not authz.allow with input as {"user": {"roles": []}, "resource": "hr", "action": "read", "trust_score": 100}
}

test_low_trust_score_is_denied_even_with_correct_role if {
    not authz.allow with input as {"user": {"roles": ["hr"]}, "resource": "hr", "action": "read", "trust_score": 20}
}

test_finance_transfer_allowed_for_finance_role if {
    authz.allow with input as {"user": {"roles": ["finance"]}, "resource": "finance", "action": "transfer", "trust_score": 100}
}

test_finance_transfer_denied_when_risk_is_high if {
    not authz.allow with input as {"user": {"roles": ["finance"]}, "resource": "finance", "action": "transfer", "trust_score": 20}
}

test_hr_cannot_make_finance_transfer if {
    not authz.allow with input as {"user": {"roles": ["hr"]}, "resource": "finance", "action": "transfer", "trust_score": 100}
}

test_finance_user_can_run_demo_device_signal if {
    authz.allow with input as {"user": {"roles": ["finance"]}, "resource": "finance", "action": "simulate_device_issue", "trust_score": 100}
}

test_hr_user_cannot_run_finance_device_simulation if {
    not authz.allow with input as {"user": {"roles": ["hr"]}, "resource": "hr", "action": "simulate_device_issue", "trust_score": 100}
}
