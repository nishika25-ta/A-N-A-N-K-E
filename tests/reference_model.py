"""Independent reference model of the policy semantics, written from docs/policy-spec.md.

It deliberately imports nothing from ``ananke`` (no evaluator, reducer, ledger or runtime) and uses
plain dicts and a different algorithm (a linear scan over the full history) so that differential
tests can catch errors in the production code. Caveat: it was written by the same implementer; an
independent reviewer should audit it (MASTERPLAN section 17).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

RULE_KINDS = ("GRANT", "DENY", "SUPERSEDE")


@dataclass
class ReferencePolicy:
    history: list[dict[str, Any]] = field(default_factory=list)  # accepted changes, in order

    def _status(self) -> dict[str, dict[str, Any]]:
        rules: dict[str, dict[str, Any]] = {}
        for ch in self.history:
            if ch["kind"] in ("GRANT", "DENY"):
                rules[ch["rule_id"]] = {**ch, "effect": ch["kind"], "status": "ACTIVE"}
            elif ch["kind"] == "REVOKE":
                rules[ch["target_rule_id"]]["status"] = "REVOKED"
            else:
                effect = rules[ch["target_rule_id"]]["effect"]
                rules[ch["target_rule_id"]]["status"] = "SUPERSEDED"
                rules[ch["rule_id"]] = {**ch, "effect": effect, "status": "ACTIVE"}
        return rules

    def accept(self, ch: dict[str, Any]) -> bool:
        """Apply a change if valid per spec section 3; return whether it was accepted."""
        rules = self._status()
        used_ids = set(rules)
        if ch.get("rule_id") is not None and ch["rule_id"] in used_ids:
            return False
        if ch["kind"] in ("REVOKE", "SUPERSEDE"):
            target = rules.get(ch["target_rule_id"])
            if target is None or target["status"] != "ACTIVE":
                return False
            if ch["kind"] == "SUPERSEDE":
                if (ch["principal_id"], ch["tool_id"]) != (
                    target["principal_id"],
                    target["tool_id"],
                ):
                    return False
                if target["effect"] == "DENY" and ch["requires_approval"]:
                    return False
        self.history.append(dict(ch))
        return True

    def decide(self, principal: str, tool: str, op: str, res: str, now: int) -> tuple[str, str]:
        """Expected (outcome, reason) for a request carrying no approval."""
        rules = self._status().values()

        def matches(r: dict[str, Any]) -> bool:
            return (r["principal_id"], r["tool_id"], r["operation"], r["resource_scope"]) == (
                principal,
                tool,
                op,
                res,
            )

        def live(r: dict[str, Any]) -> bool:
            lo, hi = r["valid_from"], r["valid_until"]
            return r["status"] == "ACTIVE" and lo <= now and (hi is None or now < hi)

        m = [r for r in rules if matches(r)]
        if any(live(r) and r["effect"] == "DENY" for r in m):
            return ("DENY", "EXPLICIT_DENY")
        live_grants = [r for r in m if live(r) and r["effect"] == "GRANT"]
        if live_grants:
            if any(r["requires_approval"] for r in live_grants):
                return ("NEEDS_APPROVAL", "APPROVAL_REQUIRED")
            return ("ALLOW", "ALLOWED")
        g = [r for r in m if r["effect"] == "GRANT"]
        if any(r["status"] != "ACTIVE" for r in g):
            return ("DENY", "GRANT_REVOKED")
        if any(
            r["status"] == "ACTIVE" and r["valid_until"] is not None and now >= r["valid_until"]
            for r in g
        ):
            return ("DENY", "GRANT_EXPIRED")
        return ("DENY", "NO_MATCHING_GRANT")
