"""Operator sessions bound to a *registered terminal* and its attestation.

A login is not "a password that works": a session is only issued when the
operator's terminal presents a fresh quote over a server-issued challenge
(the same DeviceWallet mechanism as ceremony device attestation). The issued
token therefore binds, at creation time and for its lifetime:

    person (participant_id) · duty (role) · terminal (device_id)
    · the attested software measurement · the quote timestamp (freshness)
    · an explicit expiry (attestation time validity)

Every authenticated API call re-validates the binding: the token must exist,
not be expired/superseded/logged-out, and its terminal must still be
registered and not revoked. The orchestrator library itself is untouched by
this layer — only the HTTP surface enforces it.
"""

from __future__ import annotations

import os
import time

from . import crypto
from .attestation import EnrolledDevice, verify_quote
from .errors import (
    AttestationError, AuthenticationError, NotFound,
)

DEFAULT_SESSION_TTL_SECONDS = 3600
CHALLENGE_TTL_SECONDS = 300

OPEN_SESSION = "OPEN"
LOGGED_OUT = "LOGGED_OUT"
SUPERSEDED = "SUPERSEDED"
REVOKED_SESSION = "REVOKED"       # terminal revoked while session live
EXPIRED_SESSION = "EXPIRED"


def _now(clock) -> float:
    return float(clock())


class SessionManager:
    """Stateful session/challenge records live in the store state dict.

    state["sessions"]: token_id -> session record
    state["login_challenges"]: device_id -> {challenge, created_at, consumed}
    """

    def __init__(self, state: dict, audit, clock=time.time,
                 ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS):
        self.state = state
        self.audit = audit
        self.clock = clock
        self.ttl_seconds = ttl_seconds

    # ======================================================================
    # login challenges (freshness nonce for the terminal quote)
    # ======================================================================
    def login_challenge(self, device_id: str) -> dict:
        dev = self.state["devices"].get(device_id)
        if dev is None:
            raise NotFound(f"terminal {device_id} is not registered")
        if dev.get("revoked"):
            raise AttestationError(f"terminal {device_id} is revoked")
        ch = {
            "challenge": crypto.b64e(os.urandom(32)),
            "created_at": _now(self.clock),
            "consumed": False,
        }
        self.state["login_challenges"][device_id] = ch
        self.audit.append("login_challenge_issued",
                          {"device_id": device_id})
        return {"device_id": device_id, "challenge": ch["challenge"],
                "ttl_seconds": CHALLENGE_TTL_SECONDS}

    def _take_challenge(self, device_id: str, challenge_b64: str) -> dict:
        rec = self.state["login_challenges"].get(device_id)
        if rec is None or rec.get("consumed"):
            raise AuthenticationError("no outstanding login challenge for terminal")
        age = _now(self.clock) - rec["created_at"]
        if age > CHALLENGE_TTL_SECONDS:
            raise AuthenticationError("login challenge expired; request a new one")
        import hmac
        if not hmac.compare_digest(rec["challenge"], challenge_b64):
            raise AuthenticationError("login challenge mismatch")
        rec["consumed"] = True
        return rec

    # ======================================================================
    # login: verify quote against registered terminal -> mint bound token
    # ======================================================================
    def login(self, device_id: str, challenge_b64: str, quote: dict,
              ttl_seconds: int | None = None) -> dict:
        dev_dict = self.state["devices"].get(device_id)
        if dev_dict is None:
            raise NotFound(f"terminal {device_id} is not registered")
        enrolled = EnrolledDevice.from_dict(dev_dict)
        if enrolled.revoked:
            raise AttestationError(f"terminal {device_id} is revoked")
        self._take_challenge(device_id, challenge_b64)
        verify_quote(quote, enrolled, crypto.b64d(challenge_b64),
                     now=_now(self.clock))
        participant_id = enrolled.participant_id
        person = self.state["participants"].get(participant_id)
        if person is None:
            raise NotFound(f"terminal owner {participant_id} is not enrolled")

        ttl = int(ttl_seconds if ttl_seconds is not None
                  else self.ttl_seconds)
        raw = "stk_" + crypto.b64e(os.urandom(32))
        token_id = "tok_" + crypto.digest_hex({"t": "kc-session-v1",
                                               "token": raw})[:24]
        now = _now(self.clock)
        rec = {
            "token_id": token_id,
            "participant_id": participant_id,
            "role": person["role"],
            "device_id": device_id,
            "measurement": quote["measurement"],
            "quote_ts": int(quote["ts"]),
            "seal_pub": quote["seal_pub"],
            "created_at": now,
            "expires_at": now + ttl,
            "status": OPEN_SESSION,
        }
        self.state["sessions"][token_id] = rec
        # A fresh person+terminal login supersedes earlier live sessions of
        # the same person (relogin continues against the new token).
        for other in self.state["sessions"].values():
            if (other["participant_id"] == participant_id
                    and other["status"] == OPEN_SESSION
                    and other["token_id"] != token_id):
                other["status"] = SUPERSEDED
                other["superseded_at"] = now
        self.audit.append("operator_login",
                          {"token_id": token_id,
                           "participant_id": participant_id,
                           "role": person["role"],
                           "device_id": device_id,
                           "measurement": quote["measurement"],
                           "quote_ts": quote["ts"],
                           "expires_at": rec["expires_at"]})
        return {"token": raw, **self.public_session(rec)}

    # ======================================================================
    # per-request validation
    # ======================================================================
    def _id_of(self, raw_token: str) -> str:
        return "tok_" + crypto.digest_hex(
            {"t": "kc-session-v1", "token": raw_token})[:24]

    def public_session(self, rec: dict) -> dict:
        return {k: v for k, v in rec.items()}

    def validate(self, raw_token: str) -> dict:
        if not raw_token:
            raise AuthenticationError("missing session token")
        rec = self.state["sessions"].get(self._id_of(raw_token))
        if rec is None:
            raise AuthenticationError("unknown session token")
        now = _now(self.clock)
        if rec["status"] == OPEN_SESSION and now > rec["expires_at"]:
            rec["status"] = EXPIRED_SESSION
        status = rec["status"]
        if status != OPEN_SESSION:
            raise AuthenticationError(f"session {status.lower()}")
        dev = self.state["devices"].get(rec["device_id"])
        if dev is None:
            raise AuthenticationError("terminal no longer registered")
        if dev.get("revoked"):
            rec["status"] = REVOKED_SESSION
            rec["closed_at"] = now
            raise AttestationError("terminal revoked; session invalidated")
        return rec

    def logout(self, raw_token: str) -> dict:
        rec = self.state["sessions"].get(self._id_of(raw_token))
        if rec is None:
            raise AuthenticationError("unknown session token")
        now = _now(self.clock)
        if rec["status"] == OPEN_SESSION:
            rec["status"] = LOGGED_OUT
            rec["closed_at"] = now
            self.audit.append("operator_logout",
                              {"token_id": rec["token_id"],
                               "participant_id": rec["participant_id"],
                               "device_id": rec["device_id"]})
        return self.public_session(rec)

    # ======================================================================
    # terminal revocation: invalidates every live session on the terminal
    # ======================================================================
    def revoke_terminal(self, device_id: str) -> list[str]:
        now = _now(self.clock)
        killed = []
        for rec in self.state["sessions"].values():
            if rec["device_id"] == device_id and rec["status"] == OPEN_SESSION:
                rec["status"] = REVOKED_SESSION
                rec["closed_at"] = now
                killed.append(rec["token_id"])
        return killed

    def view(self, token_id: str) -> dict | None:
        rec = self.state["sessions"].get(token_id)
        return self.public_session(rec) if rec else None

    def list_sessions(self) -> list[dict]:
        return [self.public_session(r)
                for r in self.state["sessions"].values()]
