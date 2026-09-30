"""Four-eyes authorization tickets for sensitive operator actions.

Some lifecycle changes are too consequential for a single operator session:
modifying the rule set (policies), terminating an active ceremony round,
publishing a new key generation, and purging retired key material. On the
HTTP surface each of those requires:

  1. an *authorization ticket* created by the responsible operator, freezing
     the canonical payload digest and an approval deadline;
  2. approval by a *different person*, at a *different registered terminal*,
     holding a *complementary duty*;
  3. the guarded action executes exactly once, atomically with approval.

The ticket freezes a digest of the canonicalized payload
(`crypto.dumps(sort_keys=True)`), so an approval cannot be steered to a
different target ("payload drift"). Duplicate submissions while an identical
ticket is open return the original ticket; concurrent approvals serialize on
the store lock and the action executes at most once.

The ticket closes - never executing, leaving no half-applied change - when
the token is invalid, the terminal is revoked, the payload drifts, the duties
conflict, the deadline passes, or the target state changed. Every transition
appends a hash-chained audit entry, and the full decision chain travels in
the export bundle for offline four-eyes verification.

The underlying orchestrator library is intentionally outside this module's
reach: direct callers (scripts, tests, recovery consoles) keep working; only
the web/API server routes these actions through tickets.
"""

from __future__ import annotations

import json
import os
import time

from . import crypto
from . import policy as P
from .errors import (
    AttestationError, ConflictState, Forbidden, NotFound, PayloadDrift,
    ComplementaryDutyConflict, PolicyViolation, TargetStateChanged,
    TicketClosed,
)

DEFAULT_TICKET_TTL_SECONDS = 600

POLICY_CHANGE = "POLICY_CHANGE"          # create / revise the rule set
ABORT_ACTIVE = "ABORT_ACTIVE"            # terminate an in-flight ceremony
PUBLISH_GENERATION = "PUBLISH_GENERATION"  # activate a new key generation
PURGE_RETIRED = "PURGE_RETIRED"          # zeroize retired key material

PROTECTED_OPERATIONS = (
    POLICY_CHANGE, ABORT_ACTIVE, PUBLISH_GENERATION, PURGE_RETIRED,
)

OPEN = "OPEN"
EXECUTED = "EXECUTED"
WITHDRAWN = "WITHDRAWN"
CLOSED = "CLOSED"
TERMINAL_TICKET_STATES = (EXECUTED, WITHDRAWN, CLOSED)

# close reasons (machine-readable, exported in the decision chain)
R_SESSION_EXPIRED = "session_invalid"
R_TERMINAL_REVOKED = "terminal_revoked"
R_PAYLOAD_DRIFT = "payload_drift"
R_DUTY_CONFLICT = "duty_conflict"
R_TARGET_CHANGED = "target_state_changed"
R_DEADLINE = "deadline_passed"
R_EXECUTOR = "executor_error"

# ---- duty matrix -----------------------------------------------------------
# Who may initiate each protected action, and which complementary duties may
# approve it. Approval additionally requires person != person, terminal !=
# terminal and approver duty != creator duty (the "four eyes" are disjoint).
CREATOR_DUTIES: dict[str, frozenset[str]] = {
    POLICY_CHANGE: frozenset({P.ROOT_OWNER}),
    ABORT_ACTIVE: frozenset(
        {P.ROOT_OWNER, P.KEY_STEWARD, P.ENCLAVE_OPERATOR}),
    PUBLISH_GENERATION: frozenset({P.ENCLAVE_OPERATOR, P.KEY_STEWARD}),
    PURGE_RETIRED: frozenset({P.KEY_STEWARD, P.ENCLAVE_OPERATOR}),
}
APPROVER_DUTIES: dict[str, frozenset[str]] = {
    POLICY_CHANGE: frozenset({P.WITNESS_SHAREHOLDER}),
    ABORT_ACTIVE: frozenset({P.WITNESS_SHAREHOLDER, P.ROOT_OWNER}),
    PUBLISH_GENERATION: frozenset({P.ROOT_OWNER}),
    PURGE_RETIRED: frozenset({P.WITNESS_SHAREHOLDER, P.ROOT_OWNER}),
}

# Read scopes and unguarded action capabilities per duty, enforced by the
# HTTP layer. All rostered duties may read public key material; the audit
# trail and export bundle are restricted to the security owner and the
# independent witness (the oversight pair).
#
# Cross-region recovery drills are an operational readiness exercise: the
# owner and steward design/scan/run drills; the enclave operator drives the
# isolated engine and mirroring; failover (taking the read-only verification
# ingress) is the consequential action, so acquiring its lease requires the
# owner. The independent witness may read every drill/evidence record.
READ_SCOPES: dict[str, frozenset[str]] = {
    P.ROOT_OWNER: frozenset(
        {"keys", "ceremonies", "policies", "participants",
         "audit", "export", "tickets", "sessions", "drills"}),
    P.KEY_STEWARD: frozenset(
        {"keys", "ceremonies", "policies", "participants", "tickets",
         "drills"}),
    P.WITNESS_SHAREHOLDER: frozenset(
        {"keys", "ceremonies", "policies", "participants",
         "audit", "export", "tickets", "drills"}),
    P.ENCLAVE_OPERATOR: frozenset(
        {"keys", "ceremonies", "policies", "tickets", "drills"}),
}
CAPABILITIES: dict[str, frozenset[str]] = {
    P.ROOT_OWNER: frozenset({
        "ceremony:open", "device:step", "sign:use",
        "participant:enroll", "device:revoke",
        "ticket:create", "ticket:approve", "ticket:withdraw",
        "drill:plan", "drill:scan", "drill:run", "drill:mirror",
        "drill:lease", "drill:failback", "drill:terminate",
    }),
    P.KEY_STEWARD: frozenset({
        "ceremony:open", "device:step", "sign:use",
        "ticket:create", "ticket:approve", "ticket:withdraw",
        "drill:plan", "drill:scan", "drill:run", "drill:mirror",
        "drill:failback", "drill:terminate",
    }),
    P.WITNESS_SHAREHOLDER: frozenset({
        "device:step",
        "ticket:create", "ticket:approve", "ticket:withdraw",
        "drill:mirror",
    }),
    P.ENCLAVE_OPERATOR: frozenset({
        "ceremony:open", "device:step", "sign:use",
        "ticket:create", "ticket:approve", "ticket:withdraw",
        "drill:plan", "drill:scan", "drill:run", "drill:mirror",
        "drill:failback", "drill:terminate",
    }),
}


def ticket_digest(operation: str, payload: dict) -> str:
    """Digest over the frozen canonical payload (normal JSON form)."""
    return crypto.digest_hex({"operation": operation,
                              "payload": canonical(payload)})


def canonical(payload) -> dict:
    """Round-trip through canonical encoding so key order/whitespace cannot
    produce a different digest for the same logical request."""
    return json.loads(crypto.dumps(payload))


def _now(clock) -> float:
    return float(clock())


class Authz:
    """Authorization ticket manager. All methods assume the store lock."""

    def __init__(self, state: dict, audit, sessions, clock=time.time,
                 ttl_seconds: int = DEFAULT_TICKET_TTL_SECONDS):
        self.state = state
        self.audit = audit
        self.sessions = sessions
        self.clock = clock
        self.ttl_seconds = ttl_seconds

    # ======================================================================
    # capabilities
    # ======================================================================
    @staticmethod
    def can(role: str, capability: str) -> bool:
        return capability in CAPABILITIES.get(role, frozenset())

    @classmethod
    def require_cap(cls, session: dict, capability: str):
        if not cls.can(session["role"], capability):
            raise Forbidden(
                f"duty {session['role']} may not {capability}")

    @classmethod
    def can_read(cls, role: str, scope: str) -> bool:
        return scope in READ_SCOPES.get(role, frozenset())

    # ======================================================================
    # ticket creation (idempotent: resubmit returns the original ticket)
    # ======================================================================
    def create_ticket(self, operation: str, payload: dict,
                      creator_session: dict) -> tuple[dict, bool]:
        if operation not in PROTECTED_OPERATIONS:
            raise PolicyViolation(f"unknown protected operation {operation}")
        role = creator_session["role"]
        if role not in CREATOR_DUTIES[operation]:
            raise Forbidden(
                f"duty {role} may not initiate {operation}; "
                f"requires one of {sorted(CREATOR_DUTIES[operation])}")
        frozen = canonical(payload)
        digest = ticket_digest(operation, frozen)
        # Duplicate submission: an open ticket, or the already-executed
        # ticket for exactly this operation+digest, is returned as-is.
        for t in self.state["auth_tickets"].values():
            if (t["operation"] == operation and t["digest"] == digest
                    and t["status"] in (OPEN, EXECUTED)):
                return self.public_ticket(t), True

        tid = "auth_" + crypto.b64e(crypto.digest(
            {"t": "kc-authz-v1", "operation": operation, "digest": digest,
             "r": crypto.b64e(os.urandom(8))}))[:24]
        now = _now(self.clock)
        t = {
            "id": tid,
            "operation": operation,
            "payload": frozen,
            "digest": digest,
            "status": OPEN,
            "created_at": now,
            "deadline": now + self.ttl_seconds,
            "creator": {
                "participant_id": creator_session["participant_id"],
                "role": creator_session["role"],
                "device_id": creator_session["device_id"],
                "token_id": creator_session["token_id"],
            },
            "approver": None,
            "decision_chain": [{
                "at": now, "type": "created",
                "participant_id": creator_session["participant_id"],
                "role": creator_session["role"],
                "device_id": creator_session["device_id"],
                "token_id": creator_session["token_id"],
            }],
            "execution": None,
            "closed_reason": None,
            "closed_at": None,
        }
        self.state["auth_tickets"][tid] = t
        self.audit.append("authz_ticket_created",
                          {"ticket_id": tid, "operation": operation,
                           "digest": digest, "deadline": t["deadline"],
                           "creator": t["creator"],
                           "payload": _audit_safe(frozen)})
        return self.public_ticket(t), False

    # ======================================================================
    # approval: validate everything, then execute exactly once
    # ======================================================================
    def approve(self, ticket_id: str, approver_token: str,
                executors: dict, preflights: dict | None = None,
                presented_payload: dict | None = None) -> dict:
        preflights = preflights or {}
        t = self._get(ticket_id)
        now = _now(self.clock)

        # 1. approver session must be a live, terminal-attested operator
        #    session. An invalid token closes the ticket (re-approval requires
        #    a freshly attested session and a fresh ticket).
        try:
            approver = self.sessions.validate(approver_token)
        except Exception as e:
            self._close(t, R_SESSION_EXPIRED, actor=None,
                        detail=getattr(e, "code", e.__class__.__name__))
            raise

        # 2. ticket must be OPEN and inside its frozen validity window
        current = self._refresh_status(t)
        if current != OPEN:
            raise TicketClosed(
                f"ticket {ticket_id} is {t['status']}"
                + (f" ({t['closed_reason']})" if t.get("closed_reason") else ""))

        # 3. payload drift: an approval carrying a body must hash to the
        #    frozen digest.
        if presented_payload is not None:
            if ticket_digest(t["operation"],
                             canonical(presented_payload)) != t["digest"]:
                self._close(t, R_PAYLOAD_DRIFT, actor=approver)
                raise PayloadDrift(
                    "approval payload does not match the frozen ticket digest")

        # 4. creator's own binding is still valid (person + terminal +
        #    attestation time validity). Relogin on the same terminal is a
        #    continuation; a stale token with no successor closes the ticket.
        self._check_creator_binding(t, approver)

        # 5. complementary duty: different person, different terminal,
        #    complementary (different) authorized duty.
        c = t["creator"]
        approver_roles = APPROVER_DUTIES[t["operation"]]
        if (approver["role"] not in approver_roles
                or approver["role"] == c["role"]
                or approver["participant_id"] == c["participant_id"]
                or approver["device_id"] == c["device_id"]):
            self._close(t, R_DUTY_CONFLICT, actor=approver, detail={
                "approver_role": approver["role"],
                "allowed_roles": sorted(approver_roles)})
            raise ComplementaryDutyConflict(
                f"approval needs a different person at a different terminal "
                f"with a complementary duty {sorted(approver_roles)}")

        # 6. target-state preflight against the *frozen* payload
        preflight = preflights.get(t["operation"])
        if preflight is not None:
            try:
                preflight(t["payload"])
            except (ConflictState, NotFound, PolicyViolation,
                    TargetStateChanged) as e:
                self._close(t, R_TARGET_CHANGED, actor=approver,
                            detail=getattr(e, "code", "TARGET_STATE_CHANGED"))
                raise TargetStateChanged(
                    f"guarded target changed since ticket was frozen: {e}") \
                    if not isinstance(e, TargetStateChanged) else e

        # 7. execute exactly once. The lock makes this the critical section:
        #    a concurrent approval either sees OPEN and runs, or sees
        #    EXECUTED and is rejected above.
        executor = executors.get(t["operation"])
        if executor is None:
            raise ConflictState(f"no executor registered for {t['operation']}")
        t["decision_chain"].append({
            "at": now, "type": "approved",
            "participant_id": approver["participant_id"],
            "role": approver["role"],
            "device_id": approver["device_id"],
            "token_id": approver["token_id"],
        })
        t["approver"] = {
            "participant_id": approver["participant_id"],
            "role": approver["role"],
            "device_id": approver["device_id"],
            "token_id": approver["token_id"],
            "approved_at": now,
        }
        try:
            result = executor(t["payload"])
        except Exception as e:
            # Executors validate before mutating, so no half-applied state
            # exists. Roll the pre-written "approved" link back and close the
            # ticket: a CLOSED ticket never dangles an approval without an
            # execution; its chain ends with an explicit closed link.
            t["decision_chain"].pop()
            t["approver"] = None
            self._close(t, R_EXECUTOR, actor=approver,
                        detail=getattr(e, "code", e.__class__.__name__))
            raise
        t["status"] = EXECUTED
        t["executed_at"] = _now(self.clock)
        t["execution"] = {"at": t["executed_at"],
                          "result": _audit_safe(result or {})}
        t["decision_chain"].append({
            "at": t["executed_at"], "type": "executed",
            "participant_id": approver["participant_id"],
            "role": approver["role"],
            "device_id": approver["device_id"],
            "token_id": approver["token_id"],
            "result": _audit_safe(result or {}),
        })
        self.audit.append("authz_ticket_executed",
                          {"ticket_id": t["id"],
                           "operation": t["operation"],
                           "digest": t["digest"],
                           "creator": t["creator"],
                           "approver": t["approver"],
                           "result": _audit_safe(result or {})})
        return self.public_ticket(t)

    # ======================================================================
    # withdrawal (creator only) and revocation-driven closure
    # ======================================================================
    def withdraw(self, ticket_id: str, token: str) -> dict:
        t = self._get(ticket_id)
        session = self.sessions.validate(token)
        self._refresh_status(t)
        if t["status"] != OPEN:
            raise TicketClosed(f"ticket {ticket_id} is {t['status']}")
        if session["participant_id"] != t["creator"]["participant_id"]:
            raise Forbidden("only the ticket creator may withdraw it")
        t["status"] = WITHDRAWN
        t["closed_at"] = _now(self.clock)
        t["closed_reason"] = "withdrawn_by_creator"
        t["decision_chain"].append({
            "at": t["closed_at"], "type": "withdrawn",
            "participant_id": session["participant_id"],
            "role": session["role"],
            "device_id": session["device_id"],
            "token_id": session["token_id"]})
        self.audit.append("authz_ticket_withdrawn",
                          {"ticket_id": t["id"], "operation": t["operation"],
                           "digest": t["digest"],
                           "participant_id": session["participant_id"]})
        return self.public_ticket(t)

    def close_for_terminal(self, device_id: str) -> list[str]:
        """Terminal revocation: close every live ticket created from or
        awaiting approval from that terminal."""
        closed = []
        for t in list(self.state["auth_tickets"].values()):
            if t["status"] != OPEN:
                continue
            if t["creator"]["device_id"] == device_id:
                self._close(t, R_TERMINAL_REVOKED, actor=None,
                            detail={"device_id": device_id})
                closed.append(t["id"])
        return closed

    def expire_open(self) -> int:
        n = 0
        for t in list(self.state["auth_tickets"].values()):
            if t["status"] == OPEN and _now(self.clock) > t["deadline"]:
                self._close(t, R_DEADLINE, actor=None)
                n += 1
        return n

    # ======================================================================
    # views
    # ======================================================================
    def _get(self, ticket_id: str) -> dict:
        t = self.state["auth_tickets"].get(ticket_id)
        if t is None:
            raise NotFound(f"unknown authorization ticket {ticket_id}")
        return t

    def _refresh_status(self, t: dict) -> str:
        if t["status"] == OPEN and _now(self.clock) > t["deadline"]:
            self._close(t, R_DEADLINE, actor=None)
        return t["status"]

    def get_public(self, ticket_id: str) -> dict:
        return self.public_ticket(self._get(ticket_id))

    def list_tickets(self, statuses: tuple[str, ...] | None = None) -> list[dict]:
        out = []
        for t in self.state["auth_tickets"].values():
            self._refresh_status(t)
            if statuses is None or t["status"] in statuses:
                out.append(self.public_ticket(t))
        out.sort(key=lambda t: t["created_at"])
        return out

    def public_ticket(self, t: dict) -> dict:
        return {k: t[k] for k in (
            "id", "operation", "payload", "digest", "status",
            "created_at", "deadline", "creator", "approver",
            "decision_chain", "execution", "closed_reason",
            "closed_at", "executed_at") if k in t}

    # ======================================================================
    # internals
    # ======================================================================
    def _check_creator_binding(self, t: dict, approver: dict):
        from .sessions import OPEN_SESSION
        creator_session = self.state["sessions"].get(
            t["creator"]["token_id"])
        if self._session_live(creator_session):
            return
        # continuation after relogin: a newer live session of the same person
        # on the same registered terminal keeps the ticket alive.
        pid, did = t["creator"]["participant_id"], t["creator"]["device_id"]
        renewed = any(
            self._session_live(s)
            and s["participant_id"] == pid and s["device_id"] == did
            and s["created_at"] >= t["created_at"]
            for s in self.state["sessions"].values())
        if renewed:
            return
        if self.state["devices"].get(did, {}).get("revoked"):
            self._close(t, R_TERMINAL_REVOKED, actor=approver,
                        detail={"device_id": did})
            raise AttestationError("creator terminal was revoked")
        self._close(t, R_SESSION_EXPIRED, actor=approver)
        raise TicketClosed("creator session is no longer valid; "
                           "relogin and open a new ticket")

    def _session_live(self, rec: dict | None) -> bool:
        from .sessions import OPEN_SESSION
        return bool(rec and rec["status"] == OPEN_SESSION
                    and _now(self.clock) <= rec["expires_at"])

    def _close(self, t: dict, reason: str, actor: dict | None,
               detail=None, append_decision: bool = True) -> dict:
        if t["status"] != OPEN:
            return t
        now = _now(self.clock)
        t["status"] = CLOSED
        t["closed_reason"] = reason
        t["closed_at"] = now
        if append_decision:
            entry = {"at": now, "type": "closed", "reason": reason}
            if actor is not None:
                entry.update({
                    "participant_id": actor["participant_id"],
                    "role": actor["role"],
                    "device_id": actor["device_id"],
                    "token_id": actor["token_id"]})
            if detail is not None:
                entry["detail"] = _audit_safe(detail)
            t["decision_chain"].append(entry)
        self.audit.append("authz_ticket_closed",
                          {"ticket_id": t["id"], "operation": t["operation"],
                           "digest": t["digest"], "reason": reason,
                           "detail": _audit_safe(detail)})
        return t


def _audit_safe(obj):
    """Strip anything that must not travel in audit/export (raw tokens)."""
    if isinstance(obj, dict):
        return {k: _audit_safe(v) for k, v in obj.items()
                if k != "token"}
    if isinstance(obj, (list, tuple)):
        return [_audit_safe(v) for v in obj]
    return obj
