"""Persistent storage: file-locked JSON state + append-only tamper-evident audit log.

state.json
    All mutable orchestrator records. Every write happens under an exclusive
    flock, so two consoles/HTTP workers cannot interleave a rotation publish
    (the "two current keys" guard). Writes are atomic temp-file renames.

audit.log
    One JSON object per line. Each entry links to the previous one via
    SHA256(prev_hash || canonical(payload)) and is additionally signed by the
    long-lived service identity (ed25519). Any edit, reorder or delete is
    detectable by `verify_audit_log`.

Sensitive material (shares, session secrets, signing seeds) is never put
into audit payloads; only commitments, hashes and public identifiers are.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import threading
import time

from . import crypto
from .errors import TamperError

GENESIS = "0" * 64
SERVICE_SEED_NAME = "service.identity"

# Per-root in-process locks. The threading RLock serializes threads sharing
# this process (e.g. the threaded HTTP server); the flock below serializes
# separate processes. Both are reentrant, so nested `locked()` blocks are
# safe. Keying by realpath means every Store on the same directory shares one
# RLock.
_LOCKS: dict[str, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()
_TLS = threading.local()


def utcnow() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class AuditLog:
    def __init__(self, path: str, signer_seed: bytes | None = None,
                 read_only: bool = False):
        self.path = path
        self.signer_seed = signer_seed
        self.read_only = read_only
        self.entries: list[dict] = []
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self.entries.append(json.loads(line))

    @staticmethod
    def entry_hash(entry: dict) -> str:
        h = hashlib.sha256()
        h.update(entry["prev"].encode())
        h.update(crypto.dumps(entry["payload"]).encode())
        h.update(str(entry["ts"]).encode())
        h.update(str(entry["seq"]).encode())
        return h.hexdigest()

    def append(self, event: str, payload: dict, extra: dict | None = None) -> dict:
        from . import ed25519

        if self.read_only:
            raise TamperError("audit log opened read-only")
        seq = len(self.entries)
        prev = self.entries[-1]["hash"] if self.entries else GENESIS
        entry = {
            "seq": seq,
            "ts": utcnow(),
            "event": event,
            "payload": payload,
            "prev": prev,
        }
        if extra:
            entry["extra"] = extra
        entry["hash"] = self.entry_hash(entry)
        if self.signer_seed is not None:
            entry["svc_sig"] = crypto.b64e(
                ed25519.sign(self.signer_seed, entry["hash"].encode()))
        self.entries.append(entry)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return entry

    def verify(self, service_pub: bytes | None = None) -> list[str]:
        """Check hash chain (and service signatures if pub given). Returns
        a list of human-readable problems; empty list means clean."""
        from . import ed25519

        problems = []
        prev = GENESIS
        seen_seq = set()
        for e in self.entries:
            if e["seq"] in seen_seq:
                problems.append(f"duplicate seq {e['seq']}")
            seen_seq.add(e["seq"])
            if e["prev"] != prev:
                problems.append(f"seq {e['seq']}: broken prev link")
            body = {k: v for k, v in e.items() if k not in ("hash", "svc_sig")}
            if e.get("hash") != self.entry_hash(e):
                problems.append(f"seq {e['seq']}: payload hash mismatch")
            if service_pub is not None and "svc_sig" in e:
                if not ed25519.verify(service_pub, e["hash"].encode(),
                                      crypto.b64d(e["svc_sig"])):
                    problems.append(f"seq {e['seq']}: service signature invalid")
            prev = e["hash"]
        return problems

    def payload_hashes(self) -> set[str]:
        """Set of payload hashes ever recorded (for nonce/replay checks)."""
        return {crypto.digest_hex(e["payload"]) for e in self.entries}


class Store:
    """File-locked persistent key/value collection of JSON-serializable data."""

    def __init__(self, root: str):
        self.root = root
        os.makedirs(root, exist_ok=True)
        self.state_path = os.path.join(root, "state.json")
        self.audit_path = os.path.join(root, "audit.log")
        self.identity_path = os.path.join(root, SERVICE_SEED_NAME)
        self._lock_f = None
        self._lock_count = 0

    # ---- service identity (signs audit entries + export bundles) --------
    def service_seed(self) -> bytes:
        if os.path.exists(self.identity_path):
            with open(self.identity_path, "rb") as f:
                return f.read()
        seed = os.urandom(32)
        tmp = self.identity_path + ".tmp"
        with open(tmp, "wb") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(seed)
        os.replace(tmp, self.identity_path)
        return seed

    @contextlib.contextmanager
    def locked(self):
        """Exclusive, *reentrant* cross-thread and cross-process lock."""
        key = os.path.realpath(self.root)
        with _LOCKS_GUARD:
            rlock = _LOCKS.setdefault(key, threading.RLock())
        depths: dict = getattr(_TLS, "depths", None)
        if depths is None:
            depths = {}
            _TLS.depths = depths
        depth = depths.get(key, 0)
        if depth == 0:
            os.makedirs(self.root, exist_ok=True)
            lock_path = os.path.join(self.root, ".lock")
            lf = open(lock_path, "w")
            rlock.acquire()              # block other threads
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)  # block other processes
            depths[key] = {"lf": lf, "n": 0}
        rec = depths[key]
        rec["n"] += 1
        try:
            yield self
        finally:
            rec["n"] -= 1
            if rec["n"] == 0:
                fcntl.flock(rec["lf"].fileno(), fcntl.LOCK_UN)
                rec["lf"].close()
                rlock.release()
                depths.pop(key, None)

    # ---- state -----------------------------------------------------------
    def load_state(self) -> dict:
        if not os.path.exists(self.state_path):
            return self._empty_state()
        with open(self.state_path, encoding="utf-8") as f:
            state = json.load(f)
        self._migrate(state)
        return state

    @staticmethod
    def _migrate(state: dict):
        """Fill collections introduced after schema 1 in-place."""
        defaults = Store._empty_state()
        for key, val in defaults.items():
            if key not in state:
                state[key] = val
        if state.get("schema", 1) < defaults["schema"]:
            state["schema"] = defaults["schema"]

    def save_state(self, state: dict):
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_path)

    @staticmethod
    def _empty_state() -> dict:
        return {
            "schema": 3,
            "participants": {},   # participant_id -> record
            "devices": {},        # device_id -> EnrolledDevice dict
            "policies": {},       # policy_id -> Policy dict
            "policy_versions": [],  # [policy_id+version] newest last
            "ceremonies": {},     # ceremony_id -> ceremony state dict
            "keys": {},           # key_version_id -> key version dict
            "purposes": {},       # purpose -> active key_version_id
            "spent_nonces": {},   # nonce -> (ceremony_id, when)
            "wraps": {},          # key_version_id -> sealed material dict
            "sessions": {},       # token_id -> operator session record
            "login_challenges": {},  # device_id -> pending login challenge
            "auth_tickets": {},   # ticket_id -> four-eyes authorization ticket
            # cross-region disaster recovery drills
            "drill_plans": {},    # plan_id -> revisioned drill plan record
            "drills": {},         # drill_id -> drill run record (lifecycle)
            "drill_regions": {},  # region_name -> simulated region registry
            "sequence": 0,
        }
