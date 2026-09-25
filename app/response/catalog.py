"""The approved response catalog.

The AI may only pick action NAMES from an incident's allowed_actions list.
Targets are always computed here by code from the incident evidence, so the
AI can never point an action at a user, app, or VM of its choosing.
"""

CATALOG = {
    "REVOKE_OAUTH_GRANT": {
        "label": "Revoke OAuth permission grant",
        "effect": "Deletes the delegated permission grant between the user and the app. "
                  "The app can no longer get new tokens for those scopes; access tokens already issued "
                  "stay valid until they expire (typically about an hour).",
        "reversible": "Partly: the user could consent again, so pair with Disable application.",
    },
    "DISABLE_APPLICATION": {
        "label": "Disable application",
        "effect": "Sets the app's service principal to disabled in this tenant so no user can sign in to it.",
        "reversible": "Yes: re-enable the service principal.",
    },
    "REVOKE_USER_SESSIONS": {
        "label": "Revoke user sessions",
        "effect": "Invalidates the user's refresh tokens and session cookies. "
                  "Existing access tokens remain valid until they expire (about an hour) unless the app supports CAE.",
        "reversible": "Yes: the user signs in again.",
    },
    "DISABLE_USER": {
        "label": "Disable user account",
        "effect": "Blocks sign-in for the account.",
        "reversible": "Yes: re-enable the account. Always simulated in this MVP.",
    },
    "ISOLATE_VM": {
        "label": "Isolate VM network",
        "effect": "Swaps the VM's network interface onto the pre-built isolation NSG "
                  "(deny all, except the forensics source). The original NSG is recorded for restore.",
        "reversible": "Yes: Restore network puts the original NSG back.",
    },
    "ESCALATE_INCIDENT": {
        "label": "Escalate to incident response",
        "effect": "Records an escalation. In this MVP no ticket or page is sent.",
        "reversible": "Not applicable.",
    },
    "NO_ACTION": {
        "label": "Take no action",
        "effect": "Records that no containment is needed.",
        "reversible": "Not applicable.",
    },
}

# Which actions make sense for each scenario, in recommended order.
SCENARIO_ACTIONS = {
    "oauth_consent_abuse": ["REVOKE_OAUTH_GRANT", "DISABLE_APPLICATION", "REVOKE_USER_SESSIONS",
                            "ESCALATE_INCIDENT", "NO_ACTION"],
    "session_misuse": ["REVOKE_USER_SESSIONS", "DISABLE_USER", "ESCALATE_INCIDENT", "NO_ACTION"],
    "privilege_escalation": ["ESCALATE_INCIDENT", "REVOKE_USER_SESSIONS", "DISABLE_USER", "NO_ACTION"],
    "vm_suspicious_activity": ["ISOLATE_VM", "ESCALATE_INCIDENT", "NO_ACTION"],
}

DEFAULT_RECOMMENDATION = {
    "oauth_consent_abuse": ["REVOKE_OAUTH_GRANT", "DISABLE_APPLICATION"],
    "session_misuse": ["REVOKE_USER_SESSIONS"],
    "privilege_escalation": ["ESCALATE_INCIDENT", "REVOKE_USER_SESSIONS"],
    "vm_suspicious_activity": ["ISOLATE_VM"],
}


def allowed_actions(scenario: str, severity_level: str, confidence_level: str) -> list[str]:
    actions = list(SCENARIO_ACTIONS[scenario])
    # Guardrail: for serious, reasonably-supported incidents the AI may not recommend
    # doing nothing. The analyst can still close it as a false positive.
    if severity_level in ("HIGH", "CRITICAL") and confidence_level != "LOW":
        actions.remove("NO_ACTION")
    return actions


def action_targets(scenario: str, identities: list[dict], apps: list[dict], assets: list[str]) -> dict:
    user = identities[0] if identities else {}
    app = apps[0] if apps else {}
    targets = {}
    for action in SCENARIO_ACTIONS[scenario]:
        if action == "REVOKE_OAUTH_GRANT":
            targets[action] = {"user_id": user.get("id", ""), "user_name": user.get("name", ""),
                               "app_id": app.get("app_id", ""), "app_name": app.get("name", ""),
                               "service_principal_id": app.get("service_principal_id", "")}
        elif action == "DISABLE_APPLICATION":
            targets[action] = {"app_id": app.get("app_id", ""), "app_name": app.get("name", ""),
                               "service_principal_id": app.get("service_principal_id", "")}
        elif action in ("REVOKE_USER_SESSIONS", "DISABLE_USER"):
            targets[action] = {"user_id": user.get("id", ""), "user_name": user.get("name", "")}
        elif action == "ISOLATE_VM":
            targets[action] = {"vm": assets[0] if assets else ""}
        else:
            targets[action] = {}
    return targets
